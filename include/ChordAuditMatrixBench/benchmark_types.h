/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file benchmark_types.h
 * @brief Core type definitions for the audit benchmark framework
 * @details Defines parameter configurations, benchmark results, and supporting
 *          data structures used across the entire benchmark pipeline.
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_TYPES_H
#define CAMATRIX_AUDIT_BENCHMARK_TYPES_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

// ==================================================================
// Parameter sweep mode
// ==================================================================

/**
 * @enum SweepMode
 * @brief Determines how parameter combinations are generated
 */
enum class SweepMode {
    FixedN_ScanTR,          ///< Fixed N, scan (t, r) combinations (PDP audit)
    FixedRatio_ScanN,       ///< Fixed ratios (t/N, r/N), scan N values (PDP audit)
    Identity_ScanUsers      ///< Scan user counts with fixed samples per iteration (identity verification)
};

/**
 * @enum SweepGen
 * @brief Strategy for generating a sequence of sweep sample points
 * @details Controls how a 1-D parameter axis is expanded into discrete values:
 *          - Explicit:  use a user-provided list verbatim (backward compatible)
 *          - Linear:    arithmetic progression v += step until end (inclusive)
 *          - Geometric: geometric progression v *= ratio until end (inclusive),
 *                       suited for wide-range scans (e.g. N from 100 to 100000)
 */
enum class SweepGen : std::uint8_t {
    Explicit,   ///< Use the explicitly provided values list
    Linear,     ///< v = start, start+step, start+2*step, ... <= end
    Geometric   ///< v = start, start*ratio, start*ratio^2, ... <= end
};

/**
 * @struct SeqSpec
 * @brief Specification for generating a 1-D sweep sequence
 * @details When gen == Explicit, the explicitVals vector passed to resolveSeq()
 *          is used verbatim. When gen == Linear or Geometric, start/end/step/ratio
 *          are used to generate the sequence. maxPoints is a safety guard to
 *          prevent runaway generation (e.g. step=1 with end=1e9).
 */
struct SeqSpec {
    SweepGen gen = SweepGen::Explicit;  ///< Generation strategy
    std::size_t start = 0;              ///< First value (Linear / Geometric)
    std::size_t end = 0;                ///< Inclusive upper bound (Linear / Geometric)
    std::size_t step = 0;               ///< Increment (Linear only); 0 => illegal
    double ratio = 2.0;                 ///< Multiplier (Geometric only); must be > 1.0
    std::size_t maxPoints = 1000;       ///< Safety cap on generated points
};

// ==================================================================
// Result kind
// ==================================================================

/**
 * @enum ResultKind
 * @brief Identifies the type of benchmark result
 */
enum class ResultKind : std::uint8_t {
    PdpAudit,              ///< PDP audit result (confidence rate)
    IdentityVerification   ///< Identity verification result (accuracy rate)
};

// ==================================================================
// Negative sample configuration (identity verification)
// ==================================================================

/**
 * @struct NegativeSampleConfig
 * @brief Configuration for negative sample generation in identity verification
 * @details Defines the ratios of different forgery types. The positive sample
 *          ratio is implicitly 1 - (forgeryRatio + tamperedRatio + impersonationRatio).
 */
struct NegativeSampleConfig {
    double forgeryRatio = 0.25;           ///< Ratio of forged signature samples
    double tamperedRatio = 0.25;          ///< Ratio of tampered message samples
    double impersonationRatio = 0.25;     ///< Ratio of impersonation samples
    // Positive ratio = 1.0 - sum(above)
};

// ==================================================================
// Single benchmark configuration
// ==================================================================

/**
 * @struct BenchmarkConfig
 * @brief Configuration for a single benchmark run (one parameter combination)
 */
struct BenchmarkConfig {
    // --- PDP audit fields ---
    std::size_t totalBlocks = 1000;       ///< N: total number of data blocks
    std::size_t corruptedBlocks = 10;     ///< t: number of corrupted blocks
    std::size_t sampleSize = 50;          ///< r: number of blocks sampled per audit
    std::size_t blockSize = 256;          ///< Size of each data block in bytes

    // --- Common fields ---
    std::size_t iterations = 100;         ///< Number of audit iterations per parameter combo (adjustable)
    bool usePseudoRandom = false;         ///< Whether to use deterministic PRNG for reproducibility
    std::uint64_t seed = 0;              ///< PRNG seed (only used when usePseudoRandom == true)

    // --- Identity verification fields ---
    std::size_t numUsers = 10;            ///< Number of users participating in identity verification
    std::size_t samplesPerIteration = 100;///< Number of samples verified per iteration
    NegativeSampleConfig negativeSamples; ///< Negative sample generation configuration

    // --- Dynamic PDP fields ---
    std::size_t maintenanceOps = 0;       ///< Number of maintenance operations before audit (dynamic PDP only)
};

// ==================================================================
// Parameter sweep configuration
// ==================================================================

/**
 * @struct ParameterSweep
 * @brief Configuration for sweeping multiple parameter combinations
 * @details Supports three sweep modes:
 *          - FixedN_ScanTR: PDP audit with fixed N, scanning (t, r) pairs
 *          - FixedRatio_ScanN: PDP audit with fixed ratios, scanning N values
 *          - Identity_ScanUsers: Identity verification scanning user counts
 */
struct ParameterSweep {
    SweepMode mode = SweepMode::FixedN_ScanTR;

    // --- FixedN_ScanTR mode (PDP audit) ---
    std::size_t fixedN = 1000;            ///< Fixed N value
    std::vector<std::size_t> tValues;     ///< t values to sweep (used when tSpec.gen == Explicit)
    std::vector<std::size_t> rValues;     ///< r values to sweep (used when rSpec.gen == Explicit)
    SeqSpec tSpec;                        ///< Generator spec for t axis (default Explicit => use tValues)
    SeqSpec rSpec;                        ///< Generator spec for r axis (default Explicit => use rValues)

    // --- FixedRatio_ScanN mode (PDP audit) ---
    double corruptedRatio = 0.01;         ///< t/N ratio
    double sampleRatio = 0.05;            ///< r/N ratio
    std::vector<std::size_t> nValues;     ///< N values to sweep (used when nSpec.gen == Explicit)
    SeqSpec nSpec;                        ///< Generator spec for N axis (default Explicit => use nValues)

    // --- Identity_ScanUsers mode (identity verification) ---
    std::vector<std::size_t> userValues;  ///< User counts to sweep (used when userSpec.gen == Explicit)
    SeqSpec userSpec;                     ///< Generator spec for user axis (default Explicit => use userValues)
    std::size_t samplesPerIteration = 100;///< Samples per iteration for each user count
    NegativeSampleConfig negativeSamples; ///< Negative sample configuration

    // --- Common fields ---
    std::size_t iterations = 100;         ///< Iterations per parameter combination
    bool usePseudoRandom = false;         ///< Whether to use deterministic PRNG
    std::uint64_t seed = 0;              ///< PRNG seed
    std::size_t blockSize = 256;          ///< Block size in bytes

    // --- Dynamic PDP fields ---
    std::size_t maintenanceOps = 0;       ///< Number of maintenance operations before audit (dynamic PDP only)
};

// ==================================================================
// Stage timing metrics
// ==================================================================

/**
 * @struct StageTimings
 * @brief Timing measurements for each audit pipeline stage (in milliseconds)
 */
struct StageTimings {
    // --- PDP audit stages ---
    double initAlgoMs = 0;                ///< Algorithm initialization time
    double genKeysMs = 0;                 ///< Key generation time
    double genTagsMs = 0;                 ///< Tag generation time
    double genChallengesMs = 0;           ///< Challenge generation time
    double genProofsMs = 0;               ///< Proof generation time
    double verifyProofsMs = 0;            ///< Proof verification time

    // --- Identity verification stages (0 for PDP scenarios) ---
    double signMs = 0;                    ///< Signing time
    double verifyMs = 0;                  ///< Single verification time
    double aggregateVerifyMs = 0;         ///< Aggregate verification time

    // --- Dynamic PDP stages (0 for static PDP scenarios) ---
    double maintainMs = 0;                ///< Maintenance operation time (dynamic PDP only)
};

// ==================================================================
// Message size metrics
// ==================================================================

/**
 * @struct MessageSizes
 * @brief Serialized message sizes for challenge and proof messages
 */
struct MessageSizes {
    // --- PDP audit message sizes ---
    std::size_t challengeBytes = 0;       ///< Challenge message size in bytes
    std::size_t proofBytes = 0;           ///< Proof message size in bytes

    // --- Identity verification message sizes (0 for PDP scenarios) ---
    std::size_t signatureBytes = 0;       ///< Signature message size in bytes
    std::size_t verifyRequestBytes = 0;   ///< Verify request message size in bytes
};

// ==================================================================
// Audit outcome
// ==================================================================

/**
 * @struct AuditOutcome
 * @brief Result of a single audit iteration
 */
struct AuditOutcome {
    bool detected = false;                ///< Whether data incompleteness was detected
    std::string reason;                   ///< Verification result reason
    StageTimings timings;                 ///< Per-stage timing measurements for this iteration
    MessageSizes messageSizes;            ///< Serialized message sizes for this iteration
};

// ==================================================================
// Benchmark result
// ==================================================================

/**
 * @struct BenchmarkResult
 * @brief Aggregated result for a single parameter combination
 * @details Contains both PDP audit and identity verification result fields.
 *          The ResultKind enum indicates which fields are meaningful.
 *
 *          **Static PDP** uses: totalBlocks, corruptedBlocks, sampleSize,
 *          confidenceRate, theoreticalConfidenceRate, detections.
 *          "corruptedBlocks" = number of blocks with modified content.
 *
 *          **Dynamic PDP** uses: totalBlocks, corruptedBlocks (stale versions),
 *          sampleSize, confidenceRate, theoreticalConfidenceRate, detections,
 *          maintenanceOps.
 *          "corruptedBlocks" = number of blocks with stale (outdated) versions.
 *          The same hypergeometric formula applies — only the semantic
 *          interpretation changes from "corruption detection" to "stale
 *          version detection".
 *
 *          **Identity verification** uses: numUsers, totalVerifySamples,
 *          correctVerifications, accuracyRate, TP/FP/TN/FN.
 */
struct BenchmarkResult {
    // --- Common fields ---
    ResultKind resultKind = ResultKind::PdpAudit;  ///< Type of benchmark result
    std::string algorithmType;                      ///< Algorithm type identifier (e.g., "SM9Static", "DHTDynamic")
    std::size_t iterations = 0;                     ///< Number of iterations performed

    // --- PDP audit specific (static & dynamic) ---
    std::size_t totalBlocks = 0;          ///< N: total number of data blocks
    std::size_t corruptedBlocks = 0;      ///< t: corrupted blocks (static) or stale-version blocks (dynamic)
    std::size_t sampleSize = 0;           ///< r: number of blocks sampled per audit
    double confidenceRate = 0;            ///< Audit confidence rate = detections / iterations (empirical)
    double theoreticalConfidenceRate = 0; ///< Theoretical confidence rate from hypergeometric distribution
    std::size_t totalAudits = 0;          ///< Total audit iterations performed
    std::size_t detections = 0;           ///< Number of times data incompleteness was detected

    // --- Dynamic PDP specific ---
    std::size_t maintenanceOps = 0;       ///< Number of maintenance operations performed before audit

    // --- Identity verification specific ---
    std::size_t numUsers = 0;             ///< Number of users in identity verification
    std::size_t totalVerifySamples = 0;   ///< Total number of verification samples across all iterations
    std::size_t correctVerifications = 0; ///< Number of verifications matching ground truth
    double accuracyRate = 0;              ///< Accuracy rate = (TP + TN) / (TP + FP + TN + FN)
    std::size_t trueAccepts = 0;          ///< TP: legitimate signatures correctly accepted
    std::size_t falseAccepts = 0;         ///< FP: forged signatures incorrectly accepted
    std::size_t trueRejects = 0;          ///< TN: forged signatures correctly rejected
    std::size_t falseRejects = 0;         ///< FN: legitimate signatures incorrectly rejected

    // --- Setup metrics (one-time, not averaged) ---
    StageTimings setupTimings;              ///< One-time setup stage timings

    // --- Performance metrics (per-iteration, aggregated) ---
    StageTimings avgTimings;              ///< Average per-iteration timings
    StageTimings minTimings;              ///< Minimum per-iteration timings
    StageTimings maxTimings;              ///< Maximum per-iteration timings

    // --- Resource metrics ---
    std::size_t memoryPeakBytes = 0;      ///< Peak memory usage in bytes
    MessageSizes messageSizes;            ///< Serialized message sizes
};

/**
 * @typedef AuditBenchmarkResult
 * @brief Backward-compatible alias for BenchmarkResult (deprecated)
 */
using AuditBenchmarkResult = BenchmarkResult;

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_TYPES_H
