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
 * @file pdp_audit_scenario.h
 * @brief PDP audit benchmark scenario — concrete class
 * @details Concrete BenchmarkScenario implementation for PDP (Provable Data
 *          Possession) audit algorithms. Uses AuditStrategyManager for dynamic
 *          strategy resolution, making the scenario algorithm-agnostic:
 *          construct with any algorithmType string and the corresponding
 *          strategy is resolved at runtime.
 *
 *          Supports both static and dynamic PDP strategies via StrategyKind
 *          dispatch. For static strategies (SM9Static), the pipeline is:
 *          - Setup: initAlgo → genKeys → genTags
 *          - Corruption: modify block contents while keeping Tags unchanged
 *          - Iteration: genChallenges → genProofs → verifyProofs
 *
 *          For dynamic strategies (DHTDynamic), the pipeline is:
 *          - Setup: initAlgo → genKeys → genTags → inject StateStore
 *          - Maintenance: perform Update/Insert/Delete ops via engine.maintain()
 *          - Stale versions: mark blocks as stale in StateStore (version mismatch)
 *          - Iteration: genChallenges → genProofs → verifyProofs
 *
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-08
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_PDP_AUDIT_SCENARIO_H
#define CAMATRIX_AUDIT_BENCHMARK_PDP_AUDIT_SCENARIO_H

#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Core {
class AuditEngine;
class AuditOperationContext;
class AuditStrategyManager;
class DynamicPdpStateStore;
enum class StrategyKind : std::uint8_t;
} // namespace CAMatrix::Audit::Core

namespace CAMatrix::Audit::Data {
class AuditBlockSource;
using AuditBlockSourcePtr = std::shared_ptr<AuditBlockSource>;
} // namespace CAMatrix::Audit::Data

namespace CAMatrix::Audit::Messages {
class Tags;
using TagsPtr = std::shared_ptr<Tags>;
} // namespace CAMatrix::Audit::Messages

namespace CAMatrix::Audit::Benchmark {

/**
 * @struct PdpScenarioContext
 * @brief Internal state for a PDP audit benchmark scenario
 * @details Holds the engine, operation context, data blocks, tags, and
 *          corruption state. Populated during setup(), used during iterations.
 *          For dynamic PDP, also holds the StateStore and stale version info.
 */
struct PdpScenarioContext {
    std::shared_ptr<CAMatrix::Audit::Core::AuditEngine> engine;  ///< Audit engine instance
    std::unique_ptr<CAMatrix::Audit::Core::AuditOperationContext> opCtx;  ///< Setup-stage operation context

    CAMatrix::Audit::Data::AuditBlockSourcePtr originalBlocks;    ///< Original (uncorrupted) block source
    CAMatrix::Audit::Data::AuditBlockSourcePtr corruptedBlocks;   ///< Corrupted block source (after corruptBlocks())
    CAMatrix::Audit::Messages::TagsPtr tags;                      ///< Generated tags from setup

    std::vector<std::size_t> corruptedIndices;  ///< Indices of corrupted blocks
    std::string userId;                         ///< User identifier for audit operations
    std::string fileId;                         ///< File identifier for audit operations

    StageTimings setupTimings;  ///< One-time setup stage timings

    // --- Dynamic PDP state ---
    CAMatrix::Audit::Core::StrategyKind strategyKind;  ///< Cached strategy kind for O(1) dispatch
    std::shared_ptr<CAMatrix::Audit::Core::DynamicPdpStateStore> stateStore;  ///< StateStore for dynamic PDP (owned by scenario)
    std::vector<std::size_t> staleIndices;             ///< Indices of blocks with stale versions (dynamic PDP)
};;

/**
 * @class PdpAuditScenario
 * @brief PDP audit benchmark scenario — concrete class
 * @details Algorithm-agnostic PDP audit scenario. Construct with an
 *          algorithmType string and an AuditStrategyManager; the strategy is
 *          resolved dynamically via AuditStrategyManager::getStrategy().
 *
 *          Supports both static and dynamic PDP strategies:
 *          - Static (SM9Static): corruptBlocks() modifies block content
 *          - Dynamic (DHTDynamic): markStaleVersions() creates version mismatch
 *          - prepareCorruption() dispatches based on StrategyKind automatically
 *
 *          Replaces the v1 per-algorithm subclass pattern (e.g. SM9StaticScenario)
 *          with a single concrete class that works for any PDP strategy.
 *
 * @section usage_example_pdp_scenario Usage Example
 * @code
 *     auto strategyManager = std::make_shared<InMemoryAuditStrategyManager>();
 *     strategyManager->registerStrategy(std::make_shared<SM9StaticAuditStrategy>());
 *
 *     auto scenario = std::make_unique<PdpAuditScenario>("SM9Static", strategyManager);
 *     scenario->setup(config);
 *     scenario->prepareCorruption(config.corruptedBlocks);  // dispatches to corruptBlocks()
 *     for (std::size_t i = 0; i < config.iterations; ++i) {
 *         scenario->runIteration();
 *         // ... collect metrics ...
 *     }
 *     scenario->teardown();
 * @endcode
 */
class PdpAuditScenario : public BenchmarkScenario {
public:
    /**
     * @brief Construct a PDP audit scenario
     * @param algorithmType Algorithm identifier (e.g., "SM9Static")
     * @param strategyManager Shared pointer to an AuditStrategyManager with
     *                          strategies already registered/loaded
     */
    PdpAuditScenario(const std::string& algorithmType,
                     std::shared_ptr<CAMatrix::Audit::Core::AuditStrategyManager> strategyManager);

    ~PdpAuditScenario() override = default;

    // ── BenchmarkScenario interface ──

    std::string algorithmType() const override;
    void setup(const BenchmarkConfig& config) override;
    /// @brief PDP: extracts corruptedBlocks from config and calls prepareCorruption()
    void prepare(const BenchmarkConfig& config) override;
    bool runIteration() override;
    /// @brief PDP: records lastDetected_ into the collector
    void recordIteration(MetricsCollector& collector) override;
    /// @brief Returns a PdpAuditResult populated via MetricsCollector::fillPdpResult()
    std::unique_ptr<BenchmarkResult> computeResult(
        const MetricsCollector& collector, const BenchmarkConfig& config) override;
    StageTimings getSetupTimings() const override;
    StageTimings getLastTimings() const override;
    MessageSizes getLastMessageSizes() const override;
    void teardown() override;

    // ── PDP-specific methods (still public for advanced/test use) ──

    /**
     * @brief Corrupt the specified number of data blocks (static PDP)
     * @param t Number of blocks to corrupt (modifies block content, keeps Tags unchanged)
     * @details Must be called after setup() and before runIteration().
     *          If t == 0, no corruption is applied (integrity check scenario).
     *          For static PDP strategies only.
     */
    void corruptBlocks(std::size_t t);

    /**
     * @brief Mark the specified number of blocks as having stale versions (dynamic PDP)
     * @param staleCount Number of blocks to mark as stale
     * @details Must be called after setup() and before runIteration().
     *          For dynamic PDP strategies only. Creates a version mismatch between
     *          the block metadata in the StateStore and the actual block data,
     *          simulating a scenario where the CSP has updated blocks but the
     *          TPA's DHT state is outdated.
     *          If staleCount == 0, no stale versions are created.
     */
    void markStaleVersions(std::size_t staleCount);

    /**
     * @brief Prepare corruption/stale versions based on strategy kind
     * @param t Number of blocks to corrupt (static) or mark stale (dynamic)
     * @details Dispatches based on StrategyKind:
     *          - Static: calls corruptBlocks(t)
     *          - Dynamic: calls markStaleVersions(t)
     *          Must be called after setup() and before runIteration().
     *          This is the preferred entry point for BenchmarkRunner.
     */
    void prepareCorruption(std::size_t t);

    /**
     * @brief Get whether the last iteration detected data incompleteness
     * @return true if verifyProofs detected corruption/stale versions, false otherwise
     */
    bool lastDetected() const { return lastDetected_; }

    /**
     * @brief Get the cached strategy kind
     * @return StrategyKind of the resolved strategy
     */
    CAMatrix::Audit::Core::StrategyKind strategyKind() const { return ctx_.strategyKind; }

private:
    std::string algorithmType_;
    std::shared_ptr<CAMatrix::Audit::Core::AuditStrategyManager> strategyManager_;
    PdpScenarioContext ctx_;
    PdpAuditConfig config_;

    // Last iteration results
    bool lastDetected_ = false;
    StageTimings lastTimings_;
    MessageSizes lastMessageSizes_;

    /**
     * @brief Create a deterministic random block source for benchmarking
     * @param totalBlocks Number of blocks to generate
     * @param blockSize Size of each block in bytes
     * @param seed PRNG seed for deterministic data generation
     * @return AuditBlockSourcePtr backed by MemoryAuditBlockSource
     */
    static CAMatrix::Audit::Data::AuditBlockSourcePtr makeBlockSource(
        std::size_t totalBlocks, std::size_t blockSize, std::uint64_t seed);

    /**
     * @brief Create a corrupted copy of a block source
     * @param original Original block source to copy and corrupt
     * @param t Number of blocks to corrupt
     * @param seed PRNG seed for selecting which blocks to corrupt
     * @return Pair of {corrupted source, corrupted indices}
     */
    static std::pair<CAMatrix::Audit::Data::AuditBlockSourcePtr, std::vector<std::size_t>>
    corruptBlockSource(
        const CAMatrix::Audit::Data::AuditBlockSourcePtr& original,
        std::size_t t, std::uint64_t seed);
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_PDP_AUDIT_SCENARIO_H
