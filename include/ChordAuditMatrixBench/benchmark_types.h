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
 * @version 4.0.0
 * @date 2026-07-22
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
    Explicit,   ///< Use the explicitly provided values list
    Linear,     ///< v = start, start+step, ... <= end
    Geometric   ///< v = start, start*ratio, ... <= end
};

/**
 * @struct SeqSpec
 * @brief Specification for generating a 1-D sweep sequence
 */
struct SeqSpec {
    SweepGen gen = SweepGen::Explicit;
    std::size_t start = 0;
    std::size_t end = 0;
    std::size_t step = 0;
    double ratio = 2.0;
    std::size_t maxPoints = 1000;
};

// ==================================================================
// Negative sample configuration (identity verification)
// ==================================================================

/**
 * @struct NegativeSampleConfig
 * @brief Configuration for negative sample generation in identity verification
 */
struct NegativeSampleConfig {
    double forgeryRatio = 0.25;
    double tamperedRatio = 0.25;
    double impersonationRatio = 0.25;
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

    std::size_t iterations = 100;       ///< Number of iterations — Runner loop
    bool usePseudoRandom = false;       ///< PRNG switch — read by all Scenario::setup()
    std::uint64_t seed = 0;             ///< PRNG seed — read by all Scenario::setup()
};

/**
 * @class PdpAuditConfig
 * @brief Configuration shared by all three PDP strategies (Direct/FixedRatio/InverseConfidence)
 */
class PdpAuditConfig : public BenchmarkConfig {
public:
    std::size_t totalBlocks = 1000;     ///< N — setup() generates data blocks
    std::size_t corruptedBlocks = 10;   ///< t — prepareCorruption()
    std::size_t sampleSize = 50;        ///< r — runIteration() challenge count
    std::size_t blockSize = 256;        ///< Data block size in bytes — setup()
    std::size_t maintenanceOps = 0;     ///< Dynamic PDP maintenance ops — setup()
};

/**
 * @class IdentityConfig
 * @brief Configuration for the IdentityVerify strategy
 */
class IdentityConfig : public BenchmarkConfig {
public:
    std::size_t numUsers = 10;                   ///< User count — setup() derives keys
    std::size_t samplesPerIteration = 100;       ///< Samples per iteration — generateTestSamples()
    NegativeSampleConfig negativeSamples;        ///< Negative sample config
};

// ==================================================================
// Stage timing metrics
// ==================================================================

/**
 * @struct StageTimings
 * @brief Timing measurements (ms) for each audit pipeline stage
 */
struct StageTimings {
    // --- PDP audit stages ---
    double initAlgoMs = 0;
    double genKeysMs = 0;
    double genTagsMs = 0;
    double genChallengesMs = 0;
    double genProofsMs = 0;
    double verifyProofsMs = 0;

    // --- Identity verification stages (0 for PDP) ---
    double signMs = 0;
    double verifyMs = 0;
    double aggregateVerifyMs = 0;

    // --- Dynamic PDP stages (0 for static PDP) ---
    double maintainMs = 0;
};

// ==================================================================
// Message size metrics
// ==================================================================

/**
 * @struct MessageSizes
 * @brief Serialized message sizes for challenge/proof and signature/verify messages
 */
struct MessageSizes {
    // --- PDP audit ---
    std::size_t challengeBytes = 0;
    std::size_t proofBytes = 0;

    // --- Identity verification (0 for PDP) ---
    std::size_t signatureBytes = 0;
    std::size_t verifyRequestBytes = 0;
};

// ==================================================================
// Audit outcome (single iteration)
// ==================================================================

/**
 * @struct AuditOutcome
 * @brief Result of a single audit iteration
 */
struct AuditOutcome {
    bool detected = false;
    std::string reason;
    StageTimings timings;
    MessageSizes messageSizes;
};

// ==================================================================
// Polymorphic BenchmarkResult hierarchy
// ==================================================================

/**
 * @class BenchmarkResult
 * @brief Polymorphic base for all benchmark results
 * @details Holds only the common metrics produced/reported by all scenarios.
 *          Scenario-specific metrics live in subclasses.
 */
class BenchmarkResult {
public:
    virtual ~BenchmarkResult() = default;

    std::string algorithmType;            ///< Algorithm identifier
    std::size_t iterations = 0;           ///< Iterations performed

    StageTimings setupTimings;            ///< Setup-phase timings
    StageTimings avgTimings;              ///< Average per-iteration timings
    StageTimings minTimings;              ///< Minimum per-iteration timings
    StageTimings maxTimings;              ///< Maximum per-iteration timings

    std::size_t memoryPeakBytes = 0;      ///< Peak memory usage
    MessageSizes messageSizes;            ///< Serialized message sizes
};

/**
 * @class PdpAuditResult
 * @brief Result produced by PDP strategies
 */
class PdpAuditResult : public BenchmarkResult {
public:
    std::size_t totalBlocks = 0;          ///< N
    std::size_t corruptedBlocks = 0;      ///< t
    std::size_t sampleSize = 0;           ///< r
    std::size_t maintenanceOps = 0;       ///< Dynamic PDP maintenance ops

    std::size_t detections = 0;           ///< Iterations that detected corruption
    double confidenceRate = 0;            ///< Empirical = detections / iterations
    double theoreticalConfidenceRate = 0; ///< Hypergeometric theoretical rate
};

/**
 * @class IdentityResult
 * @brief Result produced by the IdentityVerify strategy
 */
class IdentityResult : public BenchmarkResult {
public:
    std::size_t numUsers = 0;
    std::size_t totalVerifySamples = 0;
    double accuracyRate = 0;              ///< (TP + TN) / total

    std::size_t trueAccepts = 0;          ///< TP
    std::size_t falseAccepts = 0;         ///< FP
    std::size_t trueRejects = 0;          ///< TN
    std::size_t falseRejects = 0;         ///< FN
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_TYPES_H
