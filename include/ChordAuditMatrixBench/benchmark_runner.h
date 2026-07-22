/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later option.
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
 * @file benchmark_runner.h
 * @brief Orchestrates benchmark execution for a single parameter combination
 * @details The BenchmarkRunner drives the full benchmark pipeline via
 *          polymorphic virtual-method dispatch on the injected BenchmarkScenario:
 *          1. setup(config)    — one-time initialization
 *          2. prepare(config)  — pre-iteration preparation (PDP: corruption)
 *          3. runIteration()   — N iterations, each followed by recordIteration()
 *          4. teardown()       — cleanup
 *          5. computeResult()  — polymorphic BenchmarkResult
 *          Zero type switch — legacy runSweep() and scenarioKindToResultKind()
 *          have been removed (sweep orchestration now lives in CLI main).
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
#define CAMATRIX_AUDIT_BENCHMARK_RUNNER_H

#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include <cstddef>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class BenchmarkRunner
 * @brief Orchestrates execution of a benchmark scenario for one config
 * @details Owns a BenchmarkScenario; runSingle() runs the full lifecycle with
 *          pure virtual dispatch and returns a polymorphic BenchmarkResult.
 */
class BenchmarkRunner {
public:
    /**
     * @brief Construct a runner with the given scenario
     * @param scenario Algorithm-specific benchmark scenario (PDP or identity)
     */
    explicit BenchmarkRunner(std::unique_ptr<BenchmarkScenario> scenario)
        : scenario_(std::move(scenario))
    {}

    /**
     * @brief Run benchmark for a single parameter combination
     * @details Pure virtual dispatch — no if/switch/dynamic_cast.
     * @param config Benchmark configuration
     * @return Polymorphic benchmark result (PdpAuditResult or IdentityResult)
     */
    std::unique_ptr<BenchmarkResult> runSingle(const BenchmarkConfig& config)
    {
        MetricsCollector collector;

        spdlog::info("  Benchmarking iterations={} ...", config.iterations);

        // Step 1: Setup — create engine, generate keys/tags or user keys
        scenario_->setup(config);                           // virtual
        collector.recordSetupTimings(scenario_->getSetupTimings());

        // Step 2: Pre-iteration preparation (PDP: corruption; Identity: noop)
        scenario_->prepare(config);                        // virtual

        // Step 3: Run iterations
        for (std::size_t i = 0; i < config.iterations; ++i) {
            scenario_->runIteration();                     // virtual
            collector.recordTimings(scenario_->getLastTimings());
            collector.recordMessageSizes(scenario_->getLastMessageSizes());
            scenario_->recordIteration(collector);        // virtual
        }

        // Step 4: Teardown
        scenario_->teardown();                              // virtual

        // Step 5: Compute aggregated result (virtual → typed result)
        auto result = scenario_->computeResult(collector, config);
        result->algorithmType = scenario_->algorithmType();
        return result;
    }

    /**
     * @brief Get the scenario algorithm type
     */
    std::string algorithmType() const
    {
        return scenario_->algorithmType();
    }

private:
    std::unique_ptr<BenchmarkScenario> scenario_;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
