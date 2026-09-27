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
 * @file benchmark_scenario.h
 * @brief Top-level abstract interface for benchmark scenarios
 * @details Defines the polymorphic BenchmarkScenario abstract class, the
 *          common base for the PDP audit, identity verification and dynamic
 *          maintenance benchmark scenarios. Each concrete scenario implements
 *          the full virtual lifecycle: setup → prepare → runIteration →
 *          recordIteration → computeResult → teardown. Runner calls these
 *          methods polymorphically with zero type switch.
 * @author Dylan Liu
 * @version 4.2.0
 * @date 2026-09-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H
#define CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <cstddef>
#include <memory>
#include <string>

namespace CAMatrix::Audit::Benchmark {

class MetricsCollector;  // forward declaration (defined in metrics_collector.h)

/**
 * @class BenchmarkScenario
 * @brief Abstract base class for all benchmark scenarios
 * @details A BenchmarkScenario encapsulates the algorithm-specific logic for
 *          setting up the benchmark environment, running iterations, recording
 *          outcomes, and computing the aggregated result. Concrete subclasses
 *          (PdpAuditScenario, IdentityVerifyScenario, DynamicMaintenanceScenario)
 *          provide the actual implementation for each scenario type.
 *
 *          Lifecycle (all virtual — Runner calls with zero type switch):
 *          1. setup(config)       — one-time initialization (key generation, etc.)
 *          2. validateRun(config, plan) — pre-flight check against the runner's schedule
 *          3. prepare(config)     — pre-iteration preparation (PDP: corruption; default: noop)
 *          4. runIteration()      — called N times per parameter combination
 *          5. recordIteration(collector) — record per-iteration metrics (scenario-specific)
 *          6. computeResult(...)  — aggregate into a polymorphic BenchmarkResult
 *          7. teardown()          — cleanup
 *
 *          Iterations of one run are independent by default; the Runner splits
 *          them across parallel workers, each with its own scenario instance,
 *          and reports the resulting BenchmarkRunPlan through validateRun().
 *          Scenarios whose computation carries per-run state that cannot be
 *          partitioned override supportsParallelIterations() to force serial
 *          execution (Runner still creates one scenario per run).
 */
class BenchmarkScenario {
public:
    virtual ~BenchmarkScenario() = default;

    /**
     * @brief Whether one run's iterations can be partitioned across workers
     * @return true if an independently constructed scenario can execute any
     *         contiguous sub-range of the iteration loop; false forces the
     *         Runner to execute the run serially with a single scenario
     * @details Defaults to true (iterations are independent trials). Scenarios
     *          override this when an iteration depends on run-level state: the
     *          maintenance scenario reports false unless the manager resolves a
     *          dynamic strategy, and PDP audit reports false when no strategy is
     *          resolvable. Reporting false keeps the run serial, so a scenario
     *          that then rejects the config (setup() throws) fails with a clear
     *          error instead of spawning workers that all fail.
     */
    virtual bool supportsParallelIterations() const { return true; }

    /**
     * @brief Get the algorithm type identifier
     * @return Algorithm type string (e.g., "SM9Static", "SM9Noncert")
     */
    virtual std::string algorithmType() const = 0;

    /**
     * @brief One-time setup for the benchmark environment
     * @details Creates the engine, generates keys/tags, and prepares all
     *          state needed for subsequent iterations. Must be called before
     *          prepare() and runIteration().
     * @param config Benchmark configuration parameters
     */
    virtual void setup(const BenchmarkConfig& config) = 0;

    /**
     * @brief Validate the configuration against the runner's scheduling plan
     * @details Called once by the Runner after it has planned the run (effective
     *          worker count and the iteration range of every slot) and before
     *          any worker runs setup(), so a rejected configuration fails
     *          without partial work. The default accepts every combination;
     *          scenarios whose preconditions depend on the partition override
     *          this and read the plan instead of re-deriving hardware threads
     *          and slot sizes (DynamicMaintenanceScenario checks Delete
     *          capacity against the largest assigned slot).
     * @param config Benchmark configuration parameters
     * @param plan Scheduling plan the Runner is about to execute
     * @throws std::invalid_argument When @p config cannot run under @p plan
     */
    virtual void validateRun(const BenchmarkConfig& /*config*/,
                             const BenchmarkRunPlan& /*plan*/)
    {}

    /**
     * @brief Pre-iteration preparation
     * @details PDP: calls prepareCorruption(cfg.corruptedBlocks). The default
     *          is a no-op for scenarios that need no preparation (Identity,
     *          dynamic maintenance).
     * @param config Benchmark configuration parameters
     */
    virtual void prepare(const BenchmarkConfig& /*config*/) {}

    /**
     * @brief Run a single benchmark iteration
     * @details Executes the core benchmark logic for one iteration. After each
     *          call, getLastTimings() and getLastMessageSizes() reflect the
     *          metrics from this iteration and recordIteration() reports the
     *          outcome; runIteration() itself returns nothing, because
     *          "success" means a different thing to every scenario (detection,
     *          completion, accepted operation) and the Runner must not branch
     *          on it.
     */
    virtual void runIteration() = 0;

    /**
     * @brief Record per-iteration metrics into the collector
     * @details PDP: records detection outcome. Identity: records TP/FP/TN/FN
     *          per-sample outcomes from the last iteration. Dynamic
     *          maintenance: records whether the last operation succeeded.
     *          This is the only channel through which iteration outcomes reach
     *          the aggregated result.
     * @param collector MetricsCollector to record into
     */
    virtual void recordIteration(MetricsCollector& collector) = 0;

    /**
     * @brief Compute the aggregated benchmark result
     * @details Creates a polymorphic BenchmarkResult (PdpAuditResult or
     *          IdentityResult), fills it from the collector and config.
     * @param collector Aggregated metrics
     * @param config Benchmark configuration used
     * @return Polymorphic result pointer
     */
    virtual std::unique_ptr<BenchmarkResult> computeResult(
        const MetricsCollector& collector, const BenchmarkConfig& config) = 0;

    /**
     * @brief Get the timings from the most recent setup() call
     */
    virtual StageTimings getSetupTimings() const = 0;
    /**
     * @brief Get the communication metrics from the most recent setup() call
     * @details Defaults to empty: scenarios that measure no setup messages
     *          (dynamic maintenance) do not override this.
     */
    virtual MessageSizes getSetupMessageSizes() const { return {}; }

    /**
     * @brief Get the timings from the most recent runIteration() call
     */
    virtual StageTimings getLastTimings() const = 0;

    /**
     * @brief Get the message sizes from the most recent runIteration() call
     * @details Defaults to empty: scenarios that exchange no per-iteration
     *          messages (dynamic maintenance) do not override this.
     */
    virtual MessageSizes getLastMessageSizes() const { return {}; }

    /**
     * @brief Clean up resources after benchmarking
     */
    virtual void teardown() = 0;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H
