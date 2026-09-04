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
 * @details Defines polymorphic configuration / result hierarchies (PDP + Identity),
 *          supporting data structures (timings, message sizes, audit outcome),
 *          and sequence-generation utilities shared across strategies.
 *          Legacy fat structs and ResultKind/ScenarioKind/SweepMode enums have
 *          been removed in favour of an all-polymorphic pipeline.
 * @author Dylan Liu
 * @version 4.1.0
 * @date 2026-08-25
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_TYPES_H
#define CAMATRIX_AUDIT_BENCHMARK_TYPES_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

// ==================================================================
// Sequence generation helpers (shared by strategy parseAndExpand())
// ==================================================================

/**
 * @enum SweepGen
 * @brief Strategy for generating a sequence of sweep sample points
 */
enum class SweepGen : std::uint8_t {
    Explicit, /**< Use the explicitly provided values list */
    Linear, /**< v = start, start+step, ... <= end */
    Geometric /**< v = start, start*ratio, ... <= end */
};

/**
 * @struct SeqSpec
 * @brief Specification for generating a 1-D sweep sequence
 */
struct SeqSpec {
    SweepGen gen = SweepGen::Explicit; /**< Generation strategy (explicit list / linear / geometric) */
    std::size_t start = 0; /**< Sequence start (inclusive) — Linear/Geometric modes */
    std::size_t end = 0; /**< Sequence end (inclusive) — Linear/Geometric modes */
    std::size_t step = 0; /**< Step size — Linear mode (must be > 0) */
    double ratio = 2.0; /**< Growth ratio — Geometric mode (must be > 1.0) */
    std::size_t maxPoints = 1000; /**< Upper cap on generated points */
};

// ==================================================================
// Negative sample configuration (identity verification)
// ==================================================================

/**
 * @struct NegativeSampleConfig
 * @brief Configuration for negative sample generation in identity verification
 */
struct NegativeSampleConfig {
    double forgeryRatio = 0.0; /**< Fraction of samples with fully forged signatures */
    double tamperedRatio = 0.5; /**< Fraction of samples with tampered message content */
    double impersonationRatio = 0.0; /**< Fraction of samples signed by an impersonating identity */
    // Positive ratio = 1.0 - sum(above)
};

// ==================================================================
// Polymorphic BenchmarkConfig hierarchy
// ==================================================================

/**
 * @class BenchmarkConfig
 * @brief Polymorphic base for all benchmark configurations
 * @details Only fields read by ALL scenarios live here (Runner loop and all
 *          Scenario::setup()). Scenario-specific fields belong to subclasses.
 */
class BenchmarkConfig {
public:
    virtual ~BenchmarkConfig() = default;

    std::size_t iterations = 100; /**< Number of iterations — Runner loop */
    bool usePseudoRandom = false; /**< PRNG switch — read by all Scenario::setup() */
    std::uint64_t seed = 0; /**< PRNG seed — read by all Scenario::setup() */
};

/**
 * @class PdpAuditConfig
 * @brief Configuration shared by all three PDP strategies (Direct/FixedRatio/InverseConfidence)
 */
class PdpAuditConfig : public BenchmarkConfig {
public:
    std::size_t totalBlocks = 1000; /**< N — setup() generates data blocks */
    std::size_t corruptedBlocks = 10; /**< t — prepareCorruption() */
    std::size_t sampleSize = 50; /**< r — runIteration() challenge count */
    std::size_t blockSize = 256; /**< Data block size in bytes — setup() */
    std::size_t maintenanceOps = 0; /**< Dynamic PDP maintenance ops — setup() */
};

/**
 * @class IdentityConfig
 * @brief Configuration for the IdentityVerify strategy
 */
class IdentityConfig : public BenchmarkConfig {
public:
    std::size_t numUsers = 10; /**< User count — setup() derives keys */
    std::size_t samplesPerIteration = 100; /**< Samples per iteration — generateTestSamples() */
    NegativeSampleConfig negativeSamples; /**< Negative sample config */
};

// ==================================================================
// Stage timing metrics
// ==================================================================

/**
 * @struct TimingMetric
 * @brief Aggregated timing measurements for one benchmark stage
 * @details totalMs is the sum over all attempted calls, averageMs is derived
 *          from totalMs / callCount, and callCount is the number of calls
 *          included in totalMs.
 */
struct TimingMetric {
    double totalMs = 0.0;
    double averageMs = 0.0;
    std::size_t callCount = 0;
};

/**
 * @struct StageTimings
 * @brief Timing measurements for each audit pipeline stage
 */
struct StageTimings {
    // --- PDP audit stages ---
    TimingMetric initAlgorithm; /**< Algorithm initialization time */
    TimingMetric generateKeys; /**< Key generation time */
    TimingMetric generateTags; /**< Tag generation time */
    TimingMetric generateChallenges; /**< Challenge generation time */
    TimingMetric generateProofs; /**< Proof generation time */
    TimingMetric verifyProofs; /**< Proof verification time */

    // --- Identity verification stages ---
    TimingMetric sign; /**< Individual signing time */
    TimingMetric aggregateVerify; /**< Aggregate verification time */
    TimingMetric aggregate; /**< Aggregation stage timing */

    // --- Dynamic PDP stages ---
    TimingMetric maintain; /**< Dynamic PDP maintenance time */
};

// ==================================================================
// Communication metrics
// ==================================================================

/**
 * @struct MessageMetric
 * @brief Aggregated serialized message measurements for one communication stage
 * @details totalBytes is the sum over all measured messages, averageBytes is
 *          derived from totalBytes / messageCount, and messageCount is the
 *          number of messages included in totalBytes.
 */
struct MessageMetric {
    std::size_t totalBytes = 0;
    double averageBytes = 0.0;
    std::size_t messageCount = 0;
};

/**
 * @struct MessageSizes
 * @brief Serialized message measurements for audit and identity stages
 */
struct MessageSizes {
    // --- PDP audit ---
    MessageMetric tags; /**< Serialized tag-set message */
    MessageMetric challenge; /**< Serialized challenge messages */
    MessageMetric proof; /**< Serialized proof messages */

    // --- Identity verification ---
    MessageMetric keyGeneration; /**< Serialized private-key messages */
    MessageMetric signing; /**< Serialized individual-signature messages */
    MessageMetric verification; /**< Serialized aggregate-signature messages */
};


// ==================================================================
// Audit outcome (single iteration)
// ==================================================================

/**
 * @struct AuditOutcome
 * @brief Result of a single audit iteration
 */
struct AuditOutcome {
    bool detected = false; /**< Whether corruption/incompleteness was detected */
    std::string reason; /**< Human-readable detection reason */
    StageTimings timings; /**< Per-stage timings for this iteration */
    MessageSizes messageSizes; /**< Serialized message sizes for this iteration */
};

// ==================================================================
// Polymorphic BenchmarkResult hierarchy
// ==================================================================

/**
 * @class BenchmarkResult
 * @brief Polymorphic base for all benchmark results
 */
class BenchmarkResult {
public:
    virtual ~BenchmarkResult() = default;

    std::string algorithmType; /**< Algorithm identifier */
    std::size_t iterations = 0; /**< Iterations performed */

    StageTimings setupTimings; /**< Setup-phase timing metrics */
    StageTimings iterationTimings; /**< Aggregated per-iteration timing metrics */

    MessageSizes setupMessageSizes; /**< Setup-phase communication metrics */
    MessageSizes iterationMessageSizes; /**< Aggregated per-iteration communication metrics */

    std::size_t memoryPeakBytes = 0; /**< Peak memory usage */
};

/**
 * @class PdpAuditResult
 * @brief Result produced by PDP strategies
 */
class PdpAuditResult : public BenchmarkResult {
public:
    std::size_t totalBlocks = 0; /**< N */
    std::size_t corruptedBlocks = 0; /**< t */
    std::size_t sampleSize = 0; /**< r */
    std::size_t maintenanceOps = 0; /**< Dynamic PDP maintenance ops */

    std::size_t detections = 0; /**< Iterations that detected corruption */
    double confidenceRate = 0; /**< Empirical = detections / iterations */
    double theoreticalConfidenceRate = 0; /**< Hypergeometric theoretical rate */
};

/**
 * @class IdentityResult
 * @brief Result produced by the IdentityVerify strategy
 */
class IdentityResult : public BenchmarkResult {
public:
    std::size_t numUsers = 0; /**< Number of users in the identity set */
    std::size_t totalVerifySamples = 0; /**< Total samples verified across iterations */
    double averageVerifySamples = 0.0; /**< Average samples verified per iteration */
    double accuracyRate = 0; /**< (TP + TN) / total samples */

    std::size_t trueAccepts = 0; /**< Total TP across iterations */
    std::size_t falseAccepts = 0; /**< Total FP across iterations */
    std::size_t trueRejects = 0; /**< Total TN across iterations */
    std::size_t falseRejects = 0; /**< Total FN across iterations */

    double averageTrueAccepts = 0.0; /**< Average TP per iteration */
    double averageFalseAccepts = 0.0; /**< Average FP per iteration */
    double averageTrueRejects = 0.0; /**< Average TN per iteration */
    double averageFalseRejects = 0.0; /**< Average FN per iteration */

    std::string algorithmKind = "Unknown"; /**< "Online" / "Offline" / "Unknown" */
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_TYPES_H
