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
 *          common base for both PDP audit and identity verification benchmark
 *          scenarios. Each concrete scenario implements the full virtual
 *          lifecycle: setup → prepare → runIteration → recordIteration →
 *          computeResult → teardown. Runner calls these methods polymorphically
 *          with zero type switch.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
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
 *          (PdpAuditScenario, IdentityVerifyScenario) provide the actual
 *          implementation for each scenario type.
 *
 *          Lifecycle (all virtual — Runner calls with zero type switch):
 *          1. setup(config)       — one-time initialization (key generation, etc.)
 *          2. prepare(config)     — pre-iteration preparation (PDP: corruption; Identity: noop)
 *          3. runIteration()      — called N times per parameter combination
 *          4. recordIteration(collector) — record per-iteration metrics (PDP/Identity-specific)
 *          5. computeResult(...)  — aggregate into a polymorphic BenchmarkResult
 *          6. teardown()          — cleanup
 */
class BenchmarkScenario {
public:
    virtual ~BenchmarkScenario() = default;

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
     * @brief Pre-iteration preparation
     * @details PDP: calls prepareCorruption(cfg.corruptedBlocks).
     *          Identity: no-op.
     * @param config Benchmark configuration parameters
     */
    virtual void prepare(const BenchmarkConfig& config) = 0;

    /**
     * @brief Run a single benchmark iteration
     * @details Executes the core benchmark logic for one iteration. After each
     *          call, getLastTimings() and getLastMessageSizes() reflect the
     *          metrics from this iteration.
     * @return true if the iteration completed successfully, false on error
     */
    virtual bool runIteration() = 0;

    /**
     * @brief Record per-iteration metrics into the collector
     * @details PDP: records detection outcome. Identity: records TP/FP/TN/FN
     *          per-sample outcomes from the last iteration.
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
     * @brief Get the timings from the most recent runIteration() call
     */
    virtual StageTimings getLastTimings() const = 0;

    /**
     * @brief Get the message sizes from the most recent runIteration() call
     */
    virtual MessageSizes getLastMessageSizes() const = 0;

    /**
     * @brief Clean up resources after benchmarking
     */
    virtual void teardown() = 0;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H
