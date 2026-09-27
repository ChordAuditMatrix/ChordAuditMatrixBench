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
 * @details Defines polymorphic configuration / result hierarchies (PDP,
 *          dynamic maintenance, Identity), the BenchmarkRunPlan scheduling
 *          contract shared by the runner and scenarios, supporting data
 *          structures (timings, message sizes, audit outcome), and
 *          sequence-generation utilities shared across strategies. Legacy fat
 *          structs and ResultKind/ScenarioKind/SweepMode enums have been
 *          removed in favour of an all-polymorphic pipeline.
 * @author Dylan Liu
 * @version 4.2.0
 * @date 2026-09-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_TYPES_H
#define CAMATRIX_AUDIT_BENCHMARK_TYPES_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
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
    std::size_t threads = 1; /**< Requested worker threads — Runner parallel split (0 = auto: std::thread::hardware_concurrency, fallback 1) */
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
};

/**
 * @enum MaintenanceOperation
 * @brief Dynamic PDP maintenance operation exercised by the maintenance benchmark
 */
enum class MaintenanceOperation : std::uint8_t {
    Update, /**< Re-bump an existing block's metadata (version/timestamp) */
    Insert, /**< Append one new block at the end of the store */
    Delete  /**< Remove one existing block from the end of the store */
};

/**
 * @class DynamicMaintenanceConfig
 * @brief Configuration for the dynamic maintenance benchmark
 * @details Each runner worker builds its own engine, context and StateStore
 *          pre-filled with initialBlocks blocks, then executes exactly one
 *          maintenance operation per iteration against worker-local 1-based
 *          block indices (see DynamicMaintenanceScenario).
 */
class DynamicMaintenanceConfig final : public BenchmarkConfig {
public:
    std::size_t initialBlocks = 1000; /**< Blocks pre-initialized in each worker-local StateStore */
    MaintenanceOperation operation = MaintenanceOperation::Update; /**< Maintenance operation executed once per iteration */
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
// Scheduling plan (runner ↔ scenario contract)
// ==================================================================

/**
 * @class BenchmarkRunPlan
 * @brief Runner-owned scheduling plan for one benchmark run
 * @details The runner resolves the requested worker count (0 requests
 *          hardware_concurrency, fallback 1), clamps it so a run never creates
 *          more workers than iterations (a zero-iteration run still runs one
 *          worker), and splits the iterations into balanced contiguous slots:
 *          slot i covers [slotBegin(i), slotBegin(i) + slotCount(i)).
 *
 *          This plan is the single source of the split formula. The runner
 *          schedules its workers from it and hands the same instance to
 *          BenchmarkScenario::validateRun() before any worker setup, so a
 *          scenario precondition that depends on the partition (e.g. the
 *          maintenance Delete capacity guard) reads the plan instead of
 *          re-deriving hardware threads and slot sizes.
 */
class BenchmarkRunPlan {
public:
    /**
     * @brief Resolve a raw worker-count request
     * @param requested Raw --threads value (0 = hardware concurrency)
     * @return Requested worker count; std::thread::hardware_concurrency() for 0,
     *         with a fallback of 1 when the hardware count is unavailable
     */
    static std::size_t resolveThreadRequest(std::size_t requested)
    {
        if (requested == 0) {
            const unsigned hardware = std::thread::hardware_concurrency();
            return (hardware > 0) ? static_cast<std::size_t>(hardware) : 1;
        }
        return requested;
    }

    /**
     * @brief Plan a balanced split of @p iterations over @p requestedThreads
     * @param iterations Total iterations of the run
     * @param requestedThreads Raw --threads value (0 = hardware concurrency)
     * @return Plan holding the resolved request, the effective worker count
     *         (never more than the iteration count, never less than 1) and the
     *         resulting per-slot iteration ranges
     */
    static BenchmarkRunPlan balanced(std::size_t iterations, std::size_t requestedThreads)
    {
        BenchmarkRunPlan plan;
        plan.iterations_ = iterations;
        plan.requestedThreads_ = resolveThreadRequest(requestedThreads);
        plan.effectiveThreads_ = std::min(
            plan.requestedThreads_, std::max<std::size_t>(iterations, 1));
        plan.baseIterations_ = iterations / plan.effectiveThreads_;
        plan.remainderIterations_ = iterations % plan.effectiveThreads_;
        return plan;
    }

    /// @brief Resolved thread request (never 0)
    std::size_t requestedThreads() const { return requestedThreads_; }

    /// @brief Worker slots this plan schedules (at least 1, at most iterations)
    std::size_t effectiveThreads() const { return effectiveThreads_; }

    /// @brief First iteration index of @p slot (0-based, contiguous across slots)
    std::size_t slotBegin(std::size_t slot) const
    {
        return slot * baseIterations_ + std::min(slot, remainderIterations_);
    }

    /// @brief Iterations assigned to @p slot (base size, plus 1 for the first slots)
    std::size_t slotCount(std::size_t slot) const
    {
        return baseIterations_ + (slot < remainderIterations_ ? 1 : 0);
    }

    /// @brief Largest per-slot iteration count — the most one worker can be asked to run
    std::size_t largestSlotCount() const
    {
        return baseIterations_ + (remainderIterations_ > 0 ? 1 : 0);
    }

    /**
     * @brief Downgrade to a single worker covering the whole iteration range
     * @return Plan with the same resolved request but one slot
     * @details Used when a scenario reports it cannot partition its iterations
     *          (BenchmarkScenario::supportsParallelIterations() == false).
     */
    BenchmarkRunPlan asSingleWorker() const
    {
        BenchmarkRunPlan plan;
        plan.iterations_ = iterations_;
        plan.requestedThreads_ = requestedThreads_;
        plan.effectiveThreads_ = 1;
        plan.baseIterations_ = iterations_;
        return plan;
    }

private:
    std::size_t iterations_ = 0; /**< Total iterations of the planned run */
    std::size_t requestedThreads_ = 1; /**< Resolved thread request (never 0) */
    std::size_t effectiveThreads_ = 1; /**< Worker slots to schedule (≥ 1) */
    std::size_t baseIterations_ = 0; /**< Iterations per slot (base; remainder slots get +1) */
    std::size_t remainderIterations_ = 0; /**< Number of slots that get one extra iteration */
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

    // --- Dynamic maintenance ---
    TimingMetric maintain; /**< One maintenance call per iteration (DynamicMaintenanceScenario) */
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
    std::size_t requestedThreads = 1; /**< Resolved thread request (0 → std::thread::hardware_concurrency, fallback 1) */
    std::size_t effectiveThreads = 1; /**< Threads actually used — ≤ iterations; forced to 1 when the scenario cannot partition */
    double wallTimeMs = 0.0; /**< End-to-end wall time of the whole run: setup + prepare + iterations + teardown (BenchmarkRunner::runSingle) */

    StageTimings setupTimings; /**< Setup-phase timing metrics */
    StageTimings iterationTimings; /**< Aggregated per-iteration timing metrics */

    MessageSizes setupMessageSizes; /**< Setup-phase communication metrics */
    MessageSizes iterationMessageSizes; /**< Aggregated per-iteration communication metrics */

    std::size_t memoryPeakBytes = 0; /**< Peak memory usage */
};

/**
 * @class DynamicMaintenanceResult
 * @brief Result produced by the dynamic maintenance benchmark
 * @details Call totals come from the merged collector: successes + failures
 *          equal the number of maintenance calls actually attempted, which is
 *          the configured iteration count unless a worker aborted the run.
 *          Per-call latency is read from iterationTimings.maintain, whose
 *          totals aggregate every worker's calls (workers run concurrently, so
 *          that sum is aggregated call time, not wall time).
 */
class DynamicMaintenanceResult final : public BenchmarkResult {
public:
    MaintenanceOperation operation = MaintenanceOperation::Update; /**< Operation executed per iteration */
    std::size_t initialBlocks = 0; /**< Blocks pre-initialized per worker-local StateStore */
    std::size_t successfulOperations = 0; /**< Maintenance calls that returned without throwing */
    std::size_t failedOperations = 0; /**< Maintenance calls that threw and were counted as failures */

    /**
     * @brief Sum of every worker's StateStore block count after its last iteration
     * @details State-transition check for the run: Update leaves each store at
     *          initialBlocks, so the total stays initialBlocks * effectiveThreads;
     *          Insert adds one block per successful insert and Delete removes
     *          one per successful delete, so the total is
     *          initialBlocks * effectiveThreads + successfulOperations (Insert)
     *          or - successfulOperations (Delete). A rejected call changes
     *          nothing, so the identity also holds when failedOperations > 0.
     */
    std::size_t finalBlocksAcrossWorkerStores = 0;

    /**
     * @brief Successful maintenance operations per second over the whole run
     * @return successfulOperations * 1000 / wallTimeMs, 0.0 when wall time is 0
     * @details wallTimeMs is the end-to-end BenchmarkRunner measurement: it
     *          covers worker setup (engine/key/StateStore), the iteration loop
     *          and teardown, so this is a whole-run rate, NOT maintenance-only
     *          throughput. The maintenance-only per-call view is
     *          iterationTimings.maintain (totalMs / callCount / averageMs).
     */
    double endToEndOperationsPerSecond() const
    {
        return wallTimeMs > 0.0
            ? static_cast<double>(successfulOperations) * 1000.0 / wallTimeMs
            : 0.0;
    }
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
