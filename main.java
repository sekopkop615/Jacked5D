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
