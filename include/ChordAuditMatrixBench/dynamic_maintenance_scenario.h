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
 * @file dynamic_maintenance_scenario.h
 * @brief Dynamic maintenance benchmark scenario — concrete class
 * @details BenchmarkScenario implementation that measures dynamic PDP
 *          maintenance: each iteration executes exactly one Update, Insert or
 *          Delete call on the strategy's StateStore through AuditEngine.
 *
 *          Parallelism: the strategy instance is shared read-only across
 *          workers (resolved per scenario from the AuditStrategyManager), while
 *          engine, operation context and StateStore are created per worker in
 *          setup(). Iterations are therefore independent and the runner may
 *          partition them across threads; per-worker stores also mean block
 *          indices are always legal in the store the operation touches.
 *
 *          Iteration semantics (one call per iteration, 1-based indices):
 *          - Update: blockIndex = iteration % initialBlocks + 1 (round-robin);
 *          - Insert: blockIndex = current block count + 1 (append);
 *          - Delete: blockIndex = current block count (drop the tail).
 *          A rejected operation is counted as a failure, not thrown, so the
 *          run reports success/failure totals; setup() rejects a Delete config
 *          whose initialBlocks cannot cover the largest worker's delete range.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#ifndef CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_SCENARIO_H
#define CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_SCENARIO_H

#include <ChordAuditMatrixBench/benchmark_scenario.h>

#include <ChordAuditMatrixLib/interfaces/audit/audit_strategy_manager.h>
#include <ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h>
#include <ChordAuditMatrixLib/interfaces/audit/engine.h>
#include <ChordAuditMatrixLib/interfaces/audit/state_stores/dynamic_pdp_state_store.h>

#include <memory>
#include <string>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class DynamicMaintenanceScenario
 * @brief BenchmarkScenario peer of PdpAuditScenario for dynamic PDP maintenance
 * @details Lifecycle per worker: setup() resolves the dynamic strategy, builds
 *          the worker's own engine, initializes the algorithm, generates keys
 *          and creates a StateStore pre-filled with initialBlocks blocks;
 *          prepare() is a no-op; every runIteration() performs one maintenance
 *          call; computeResult() fills a DynamicMaintenanceResult from the
 *          merged collector; teardown() drops the worker-local state.
 *          The maintenance benchmark never runs inside PDP audit scenarios —
 *          PDP iterations only generate challenges, proofs and verification.
 */
class DynamicMaintenanceScenario final : public BenchmarkScenario {
public:
    /**
     * @brief Construct a dynamic maintenance scenario
     * @param algorithmType Dynamic strategy identifier (e.g., "DHTDynamic")
     * @param strategyManager Shared manager containing the selected strategy
     * @throws std::invalid_argument When @p strategyManager is null
     * @details The manager (and the strategy it resolves) is shared read-only
     *          across workers; each worker's scenario owns its engine, context
     *          and StateStore.
     */
    DynamicMaintenanceScenario(
        std::string algorithmType,
        std::shared_ptr<CAMatrix::Audit::Core::AuditStrategyManager> strategyManager);

    /// @brief Whether one run's iterations can be partitioned across workers
    /// @return true when the manager resolves a dynamic strategy; false keeps
    ///         the runner serial and lets setup() reject the config clearly
    bool supportsParallelIterations() const override;
    /// @brief Returns the algorithm type identifier
    std::string algorithmType() const override;
    /// @brief One-time setup: engine, algorithm init, keys, worker-local StateStore
    /// @param config Dynamic maintenance benchmark configuration
    /// @throws std::invalid_argument On a non-maintenance config, a non-dynamic
    ///         strategy, zero initial blocks, or a Delete config whose
    ///         initialBlocks cannot cover the largest worker's delete range
    void setup(const BenchmarkConfig& config) override;
    /// @brief No-op: maintenance iterations need no pre-iteration preparation
    /// @param config Dynamic maintenance benchmark configuration
    void prepare(const BenchmarkConfig& config) override;
    /// @brief Execute one maintenance call on this worker's StateStore
    /// @return true when the operation succeeded, false when it was rejected
    bool runIteration() override;
    /// @brief Records the last maintenance outcome (success/failure) into the collector
    /// @param collector MetricsCollector to record into
    void recordIteration(MetricsCollector& collector) override;
    /// @brief Returns a DynamicMaintenanceResult filled from the merged collector
    /// @param collector Aggregated metrics
    /// @param config Dynamic maintenance benchmark configuration
    /// @return Polymorphic maintenance result pointer
    std::unique_ptr<BenchmarkResult> computeResult(
        const MetricsCollector& collector, const BenchmarkConfig& config) override;
    /// @brief Returns setup stage timings (algorithm init, key generation)
    StageTimings getSetupTimings() const override;
    /// @brief Returns empty setup message sizes (maintenance measures no messages)
    MessageSizes getSetupMessageSizes() const override;
    /// @brief Returns the maintenance timing of the most recent iteration
    StageTimings getLastTimings() const override;
    /// @brief Returns empty iteration message sizes (maintenance measures no messages)
    MessageSizes getLastMessageSizes() const override;
    /// @brief Drops engine, context, StateStore and per-run counters
    void teardown() override;

private:
    std::string algorithmType_;
    std::shared_ptr<CAMatrix::Audit::Core::AuditStrategyManager> strategyManager_;
    std::shared_ptr<CAMatrix::Audit::Core::AuditStrategy> strategy_;
    std::shared_ptr<CAMatrix::Audit::Core::AuditEngine> engine_;
    std::shared_ptr<CAMatrix::Audit::Core::DynamicPdpStateStore> stateStore_;
    CAMatrix::Audit::Core::AuditOperationContext baseContext_; /**< Worker-local context (strategy + StateStore + setup results) reused by every iteration */
    DynamicMaintenanceConfig config_;
    std::string fileId_;
    std::size_t localIteration_ = 0; /**< Iterations already executed by this worker */
    StageTimings setupTimings_;
    StageTimings lastTimings_;
    bool lastSucceeded_ = false;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_SCENARIO_H
