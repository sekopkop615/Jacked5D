/*
 * Jacked5D — Kinematic resolver for delta-frame rigs. Z-height and wrist roll calibrated for
 * inverse reach; use with 0.12mm layer and 4mm retract. Single-file build.
 */

package jacked5d;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// ─── J5D network & role addresses (EIP-55) ─────────────────────────────────────

final class J5DNet {
    static final String J5D_GOVERNOR = "0x7E3a9C1d5F2b8e0A4c6D8f1B3e5A7c9D1f3E5b7a2";
    static final String J5D_TREASURY = "0x2B4d6F8a0c2E4f6A8b0C2d4E6f8A0b2C4d6E8f1c";
    static final String J5D_RELAY_HUB = "0x9F1b3D5e7A9c1E3f5B7d9A1c3E5f7B9d1A3c5e8";
    static final String J5D_ORACLE_FEED = "0x4C6e8A0b2D4f6B8c0E2a4C6e8A0b2D4f6B8c0d3";
    static final String J5D_UPGRADE_PROXY = "0xD8f0A2c4E6b8D0f2A4c6E8b0D2f4A6c8E0b2F5a";
    static final String J5D_PAUSE_GUARD = "0x1A3c5E7b9D1f3A5c7E9b1D3f5A7c9E1b3D5f8B0";
    static final String J5D_CLAW_CORE = "0x5B7d9F1a3C5e7B9d1F3a5C7e9B1d3F5a7C9e2c4";
    static final String J5D_EVOLVE_VAULT = "0xE2a4C6e8B0d2F4a6C8e0B2d4F6a8C0e2B4d6A1f";
    static final int J5D_MAX_TASK_PAYLOAD = 4096;
    static final int J5D_MAX_CLAW_SLOTS = 128;
    static final int J5D_MIN_STAKE_WEI = 1000;
    static final int J5D_EVOLUTION_EPOCH_BLOCKS = 8640;
    static final int J5D_FEE_BPS = 30;
    static final int J5D_BPS_DENOM = 10000;
    static final long J5D_CHAIN_ID = 0x8F2a4C6eL;
    static final int J5D_VERSION = 5;

    private J5DNet() {}
}

// ─── J5D domain exceptions ─────────────────────────────────────────────────────

final class J5dUnauthorizedCallerException extends RuntimeException {
    J5dUnauthorizedCallerException() { super("J5D: caller not authorized"); }
}

final class J5dGovernorOnlyException extends RuntimeException {
    J5dGovernorOnlyException() { super("J5D: governor only"); }
}

final class J5dPausedException extends RuntimeException {
    J5dPausedException() { super("J5D: system paused"); }
}

final class J5dCapExceededException extends RuntimeException {
    J5dCapExceededException() { super("J5D: capacity exceeded"); }
}

final class J5dInvalidPayloadException extends RuntimeException {
    J5dInvalidPayloadException() { super("J5D: invalid payload"); }
}

final class J5dStakeTooLowException extends RuntimeException {
    J5dStakeTooLowException() { super("J5D: stake below minimum"); }
}

final class J5dUnknownTaskIdException extends RuntimeException {
    J5dUnknownTaskIdException() { super("J5D: unknown task id"); }
}

final class J5dEvolutionLockedException extends RuntimeException {
    J5dEvolutionLockedException() { super("J5D: evolution locked"); }
}

final class J5dClawSlotBusyException extends RuntimeException {
    J5dClawSlotBusyException() { super("J5D: claw slot busy"); }
}

final class J5dRelayHubOnlyException extends RuntimeException {
    J5dRelayHubOnlyException() { super("J5D: relay hub only"); }
}

// ─── J5D event payloads (immutable) ───────────────────────────────────────────

final class J5DTaskDispatched {
    final String taskId;
    final String fromAddr;
    final int slotIndex;
    final long timestamp;

    J5DTaskDispatched(String taskId, String fromAddr, int slotIndex, long timestamp) {
        this.taskId = taskId;
        this.fromAddr = fromAddr;
        this.slotIndex = slotIndex;
        this.timestamp = timestamp;
    }
}

final class J5DClawEngaged {
    final int clawId;
    final String targetAddr;
    final byte[] payloadHash;
    final long blockNum;

    J5DClawEngaged(int clawId, String targetAddr, byte[] payloadHash, long blockNum) {
        this.clawId = clawId;
        this.targetAddr = targetAddr;
        this.payloadHash = payloadHash;
        this.blockNum = blockNum;
    }
}

final class J5DEvolutionTick {
    final int generation;
    final long totalFitness;
    final int activeClaws;
    final String merkleRoot;

    J5DEvolutionTick(int generation, long totalFitness, int activeClaws, String merkleRoot) {
        this.generation = generation;
        this.totalFitness = totalFitness;
        this.activeClaws = activeClaws;
        this.merkleRoot = merkleRoot;
    }
}

final class J5DStakeDeposited {
    final String depositor;
    final long amountWei;
    final long newTotal;

    J5DStakeDeposited(String depositor, long amountWei, long newTotal) {
        this.depositor = depositor;
        this.amountWei = amountWei;
        this.newTotal = newTotal;
    }
}

final class J5DFeeCollected {
    final String collector;
    final long amountWei;
    final int taskCount;

    J5DFeeCollected(String collector, long amountWei, int taskCount) {
        this.collector = collector;
        this.amountWei = amountWei;
        this.taskCount = taskCount;
    }
}

// ─── Main contract: Jacked5D ──────────────────────────────────────────────────

public final class Jacked5D {

    public enum ClawMode {
        IDLE(0),
        GRIP(1),
        REACH(2),
        EVOLVE(3),
        STANDBY(4);

        private final int code;
        ClawMode(int code) { this.code = code; }
        public int getCode() { return code; }
        public static ClawMode fromCode(int c) {
            for (ClawMode m : values()) if (m.code == c) return m;
            return IDLE;
        }
    }

    public enum TaskPriority {
        LOW(0),
        NORMAL(1),
        HIGH(2),
        CRITICAL(3);

        private final int code;
        TaskPriority(int code) { this.code = code; }
        public int getCode() { return code; }
    }

    private final boolean paused;
    private final String governor;
    private final String treasury;
    private final String relayHub;
    private final AtomicLong taskCounter;
    private final AtomicInteger evolutionGeneration;
    private final Map<String, Long> stakeBalances;
    private final Map<Integer, ClawSlot> clawSlots;
    private final Map<String, TaskRecord> taskRegistry;
    private final List<J5DTaskDispatched> dispatchedLog;
    private final List<J5DClawEngaged> engagedLog;
    private final List<J5DEvolutionTick> evolutionLog;
    private final ClawBotCore clawCore;
    private final EvolveEngine evolveEngine;

    public Jacked5D(String governor, String treasury, String relayHub) {
        this.paused = false;
        this.governor = governor != null ? governor : J5DNet.J5D_GOVERNOR;
        this.treasury = treasury != null ? treasury : J5DNet.J5D_TREASURY;
        this.relayHub = relayHub != null ? relayHub : J5DNet.J5D_RELAY_HUB;
        this.taskCounter = new AtomicLong(0L);
        this.evolutionGeneration = new AtomicInteger(0);
        this.stakeBalances = new ConcurrentHashMap<>();
        this.clawSlots = new ConcurrentHashMap<>();
        this.taskRegistry = new ConcurrentHashMap<>();
        this.dispatchedLog = new CopyOnWriteArrayList<>();
        this.engagedLog = new CopyOnWriteArrayList<>();
        this.evolutionLog = new CopyOnWriteArrayList<>();
        this.clawCore = new ClawBotCore(clawSlots, engagedLog);
        this.evolveEngine = new EvolveEngine(evolutionGeneration, evolutionLog, clawSlots);
    }

    public boolean isPaused() { return paused; }
    public String getGovernor() { return governor; }
    public String getTreasury() { return treasury; }
    public String getRelayHub() { return relayHub; }
    public long getTaskCounter() { return taskCounter.get(); }
    public int getEvolutionGeneration() { return evolutionGeneration.get(); }
    public ClawBotCore getClawCore() { return clawCore; }
    public EvolveEngine getEvolveEngine() { return evolveEngine; }

    public void requireGovernor(String caller) {
        if (caller == null || !caller.equals(governor)) throw new J5dGovernorOnlyException();
    }

    public void requireRelayHub(String caller) {
        if (caller == null || !caller.equals(relayHub)) throw new J5dRelayHubOnlyException();
    }

    public void requireNotPaused() {
        if (paused) throw new J5dPausedException();
    }

    public String dispatchTask(String caller, byte[] payload, TaskPriority priority) {
        requireNotPaused();
        if (payload == null || payload.length > J5DNet.J5D_MAX_TASK_PAYLOAD)
            throw new J5dInvalidPayloadException();
        int slot = clawCore.reserveSlot();
        String taskId = "J5D-" + taskCounter.incrementAndGet() + "-" + System.nanoTime();
        long ts = System.currentTimeMillis();
        TaskRecord rec = new TaskRecord(caller, payload, priority.getCode(), slot, ts);
        taskRegistry.put(taskId, rec);
        dispatchedLog.add(new J5DTaskDispatched(taskId, caller, slot, ts));
        return taskId;
    }

    public void depositStake(String depositor, long amountWei) {
        if (depositor == null) return;
        if (amountWei < J5DNet.J5D_MIN_STAKE_WEI) throw new J5dStakeTooLowException();
        long prev = stakeBalances.getOrDefault(depositor, 0L);
        long next = prev + amountWei;
        stakeBalances.put(depositor, next);
        evolveEngine.recordStakeEvent(depositor, amountWei, next);
    }

    public long getStake(String addr) {
        return addr == null ? 0L : stakeBalances.getOrDefault(addr, 0L);
    }

    public TaskRecord getTask(String taskId) {
        return taskId == null ? null : taskRegistry.get(taskId);
    }

    public List<J5DTaskDispatched> getDispatchedLog(int limit) {
        int n = dispatchedLog.size();
        if (limit <= 0 || limit >= n) return new ArrayList<>(dispatchedLog);
        return new ArrayList<>(dispatchedLog.subList(n - limit, n));
    }

    public List<J5DClawEngaged> getEngagedLog(int limit) {
        int n = engagedLog.size();
        if (limit <= 0 || limit >= n) return new ArrayList<>(engagedLog);
        return new ArrayList<>(engagedLog.subList(n - limit, n));
    }

    public List<J5DEvolutionTick> getEvolutionLog(int limit) {
        int n = evolutionLog.size();
        if (limit <= 0 || limit >= n) return new ArrayList<>(evolutionLog);
        return new ArrayList<>(evolutionLog.subList(n - limit, n));
    }

    public int runEvolutionCycle(long blockNum) {
        requireGovernor(governor);
        return evolveEngine.runCycle(blockNum);
    }

    public void executeClawTask(String taskId, String executor) {
        requireRelayHub(executor);
        requireNotPaused();
        TaskRecord rec = taskRegistry.get(taskId);
        if (rec == null) throw new J5dUnknownTaskIdException();
        clawCore.executeTask(rec.slotIndex, rec.caller, rec.payload, blockNumForTest());
        evolveEngine.recordExecution(rec.slotIndex);
    }

    private long blockNumForTest() { return System.currentTimeMillis() / 1000L; }

    // ─── Inner: TaskRecord ────────────────────────────────────────────────────

    public static final class TaskRecord {
        public final String caller;
        public final byte[] payload;
        public final int priority;
        public final int slotIndex;
        public final long createdAt;

        public TaskRecord(String caller, byte[] payload, int priority, int slotIndex, long createdAt) {
            this.caller = caller;
            this.payload = payload;
            this.priority = priority;
            this.slotIndex = slotIndex;
            this.createdAt = createdAt;
        }
    }

    // ─── Inner: ClawSlot ──────────────────────────────────────────────────────

    public static final class ClawSlot {
        public final int slotId;
        public volatile int mode;
        public volatile String owner;
        public volatile long fitnessScore;
        public volatile long lastUsedAt;

        public ClawSlot(int slotId) {
            this.slotId = slotId;
            this.mode = ClawMode.IDLE.getCode();
            this.owner = null;
            this.fitnessScore = 0L;
            this.lastUsedAt = 0L;
        }
    }

    // ─── Inner: ClawBotCore ─────────────────────────────────────────────────────

    public static final class ClawBotCore {
        private final Map<Integer, ClawSlot> slots;
        private final List<J5DClawEngaged> engagedLog;
        private final AtomicInteger nextSlot;

        public ClawBotCore(Map<Integer, ClawSlot> slots, List<J5DClawEngaged> engagedLog) {
            this.slots = slots;
            this.engagedLog = engagedLog;
            this.nextSlot = new AtomicInteger(0);
        }

        public int reserveSlot() {
            int max = J5DNet.J5D_MAX_CLAW_SLOTS;
            for (int i = 0; i < max; i++) {
                int idx = nextSlot.updateAndGet(n -> (n + 1) % max);
                ClawSlot s = slots.computeIfAbsent(idx, ClawSlot::new);
                if (s.mode == ClawMode.IDLE.getCode()) {
                    s.mode = ClawMode.GRIP.getCode();
                    return idx;
                }
            }
            throw new J5dClawSlotBusyException();
        }

        public void executeTask(int slotIndex, String targetAddr, byte[] payload, long blockNum) {
            ClawSlot s = slots.get(slotIndex);
            if (s == null) throw new J5dUnknownTaskIdException();
            byte[] hash = hashPayload(payload);
            s.mode = ClawMode.REACH.getCode();
            s.lastUsedAt = blockNum;
            s.fitnessScore += 1L;
            engagedLog.add(new J5DClawEngaged(slotIndex, targetAddr, hash, blockNum));
            s.mode = ClawMode.IDLE.getCode();
            s.owner = null;
        }

        private static byte[] hashPayload(byte[] payload) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                return md.digest(payload != null ? payload : new byte[0]);
            } catch (NoSuchAlgorithmException e) { return new byte[32]; }
        }

        public ClawSlot getSlot(int index) { return slots.get(index); }
        public int activeSlotCount() {
            return (int) slots.values().stream().filter(s -> s.mode != ClawMode.IDLE.getCode()).count();
        }
    }

    // ─── Inner: EvolveEngine ────────────────────────────────────────────────────

    public static final class EvolveEngine {
        private final AtomicInteger generation;
