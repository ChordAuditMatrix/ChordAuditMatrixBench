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
 * @brief Orchestrates benchmark execution across parameter combinations
 * @details The BenchmarkRunner drives the full benchmark pipeline for both
 *          PDP audit and identity verification scenarios:
 *          1. Expands a ParameterSweep into individual configs
 *          2. For each config: setup → iterate → collect metrics
 *          3. Produces a vector of BenchmarkResult
 *
 *          ScenarioKind dispatch:
 *          - PdpAudit: setup → prepareCorruption → runIteration (recordOutcome)
 *            - Static PDP: corruptBlocks (flip bits)
 *            - Dynamic PDP: markStaleVersions (version mismatch)
 *          - IdentityVerification: setup → runIteration (recordIdentityOutcome)
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-08
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
#define CAMATRIX_AUDIT_BENCHMARK_RUNNER_H

#include <ChordAuditMatrixBench/benchmark_config.h>
#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/identity_verify_scenario.h>
#include <ChordAuditMatrixBench/metrics_collector.h>
#include <ChordAuditMatrixBench/pdp_audit_scenario.h>

#include <chrono>
#include <cstddef>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @brief Map ScenarioKind to the corresponding ResultKind
 * @param kind Scenario type identifier
 * @return ResultKind enum value for result computation
 */
inline ResultKind scenarioKindToResultKind(ScenarioKind kind)
{
    switch (kind) {
    case ScenarioKind::PdpAudit:
        return ResultKind::PdpAudit;
    case ScenarioKind::IdentityVerification:
        return ResultKind::IdentityVerification;
    }
    return ResultKind::PdpAudit; // fallback (unreachable with complete switch)
}

/**
 * @class BenchmarkRunner
 * @brief Orchestrates the execution of a benchmark scenario
 * @details Manages the full lifecycle of benchmark execution: expanding
 *          parameter sweeps, running iterations with metrics collection,
 *          and producing aggregated results. Supports both PDP audit and
 *          identity verification scenarios via ScenarioKind dispatch.
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
     * @param config Benchmark configuration
     * @return Aggregated benchmark result
     */
    BenchmarkResult runSingle(const BenchmarkConfig& config)
    {
        MetricsCollector collector;
        const auto resultKind = scenarioKindToResultKind(scenario_->kind());
        const auto algoType = scenario_->algorithmType();

        if (resultKind == ResultKind::PdpAudit) {
            spdlog::info("  Benchmarking N={} t={} r={} iterations={} ...",
                        config.totalBlocks, config.corruptedBlocks,
                        config.sampleSize, config.iterations);
        } else {
            spdlog::info("  Benchmarking users={} samples={} iterations={} ...",
                        config.numUsers, config.samplesPerIteration,
                        config.iterations);
        }

        // Step 1: Setup — create engine, generate keys/tags or user keys
        scenario_->setup(config);
        collector.recordSetupTimings(scenario_->getSetupTimings());

        // Step 2: Scenario-specific pre-iteration setup
        if (resultKind == ResultKind::PdpAudit) {
            // PDP: prepare corruption/stale versions before iterations
            // Static PDP: corrupts t blocks (flip bits)
            // Dynamic PDP: marks t blocks as stale (version mismatch)
            auto* pdp = dynamic_cast<PdpAuditScenario*>(scenario_.get());
            if (pdp) {
                if (config.corruptedBlocks > 0) {
                    pdp->prepareCorruption(config.corruptedBlocks);
                }
            }
        }
        // Identity: no pre-iteration setup needed (test samples generated in setup)

        // Step 3: Run iterations
        for (std::size_t i = 0; i < config.iterations; ++i) {
            scenario_->runIteration();
            collector.recordTimings(scenario_->getLastTimings());
            collector.recordMessageSizes(scenario_->getLastMessageSizes());

            if (resultKind == ResultKind::PdpAudit) {
                // PDP: record detection outcome
                auto* pdp = dynamic_cast<PdpAuditScenario*>(scenario_.get());
                bool detected = pdp ? pdp->lastDetected() : false;
                collector.recordOutcome(detected, "");
            } else {
                // Identity: record per-sample verification outcomes
                auto* identity = dynamic_cast<IdentityVerifyScenario*>(scenario_.get());
                if (identity) {
                    // TP: accepted && shouldAccept
                    for (std::size_t tp = 0; tp < identity->lastTrueAccepts(); ++tp)
                        collector.recordIdentityOutcome(true, true);
                    // FP: accepted && !shouldAccept
                    for (std::size_t fp = 0; fp < identity->lastFalseAccepts(); ++fp)
                        collector.recordIdentityOutcome(true, false);
                    // TN: !accepted && !shouldAccept
                    for (std::size_t tn = 0; tn < identity->lastTrueRejects(); ++tn)
                        collector.recordIdentityOutcome(false, false);
                    // FN: !accepted && shouldAccept
                    for (std::size_t fn = 0; fn < identity->lastFalseRejects(); ++fn)
                        collector.recordIdentityOutcome(false, true);
                }
            }
        }

        // Step 4: Teardown
        scenario_->teardown();

        auto result = collector.computeResult(config, resultKind, algoType);

        if (resultKind == ResultKind::PdpAudit) {
            result.theoreticalConfidenceRate = theoreticalConfidenceRate(
                config.totalBlocks, config.corruptedBlocks, config.sampleSize);
            spdlog::info("confidence={:.2f} theoretical={:.2f}",
                        result.confidenceRate, result.theoreticalConfidenceRate);
        } else {
            spdlog::info("accuracy={} (TP={} FP={} TN={} FN={})",
                        result.accuracyRate, result.trueAccepts,
                        result.falseAccepts, result.trueRejects,
                        result.falseRejects);
        }

        return result;
    }

    /**
     * @brief Run benchmark across a parameter sweep
     * @param sweep Parameter sweep configuration
     * @return Vector of benchmark results, one per parameter combination
     */
    std::vector<BenchmarkResult> runSweep(const ParameterSweep& sweep)
    {
        auto configs = expandSweep(sweep);
        std::vector<BenchmarkResult> results;
        results.reserve(configs.size());

        const auto resultKind = scenarioKindToResultKind(scenario_->kind());
        const char* kindLabel = (resultKind == ResultKind::PdpAudit)
            ? "PDP Audit Benchmark" : "Identity Verification Benchmark";

        spdlog::info("\n=== {} : {} ===", kindLabel, scenario_->algorithmType());
        spdlog::info("Parameter combinations: {}", configs.size());

        for (const auto& cfg : configs) {
            results.push_back(runSingle(cfg));
        }

        spdlog::info("\n=== Benchmark Complete ===");
        return results;
    }

    /**
     * @brief Get the scenario algorithm type
     * @return Algorithm type string
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
