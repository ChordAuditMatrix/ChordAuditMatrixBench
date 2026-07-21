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
 * @details Defines the ScenarioKind enum and the BenchmarkScenario abstract
 *          class, which serves as the common base for both PDP audit and
 *          identity verification benchmark scenarios. Each concrete scenario
 *          encapsulates algorithm-specific setup, iteration, and teardown
 *          logic while sharing the BenchmarkConfig / BenchmarkResult /
 *          MetricsCollector infrastructure.
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H
#define CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace CAMatrix::Audit::Benchmark {

/**
 * @enum ScenarioKind
 * @brief Identifies the type of benchmark scenario
 */
enum class ScenarioKind : std::uint8_t {
    PdpAudit,              ///< PDP audit scenario (challenge-proof-verify)
    IdentityVerification   ///< Identity verification scenario (sign-verify)
};

/**
 * @class BenchmarkScenario
 * @brief Abstract base class for all benchmark scenarios
 * @details A BenchmarkScenario encapsulates the algorithm-specific logic for
 *          setting up the benchmark environment, running a single iteration,
 *          and collecting timing/message-size metrics. Concrete subclasses
 *          (PdpAuditScenario, IdentityVerifyScenario) provide the actual
 *          implementation for each scenario type.
 *
 *          Lifecycle:
 *          1. setup(config)   — one-time initialization (key generation, etc.)
 *          2. runIteration()  — called N times per parameter combination
 *          3. teardown()      — cleanup
 */
class BenchmarkScenario {
public:
    virtual ~BenchmarkScenario() = default;

    /**
     * @brief Get the scenario type identifier
     * @return ScenarioKind enum value
     */
    virtual ScenarioKind kind() const = 0;

    /**
     * @brief Get the algorithm type identifier
     * @return Algorithm type string (e.g., "SM9Static", "SM9Noncert")
     */
    virtual std::string algorithmType() const = 0;

    /**
     * @brief One-time setup for the benchmark environment
     * @details Creates the engine, generates keys/tags, and prepares all
     *          state needed for subsequent iterations. Must be called before
     *          runIteration().
     * @param config Benchmark configuration parameters
     */
    virtual void setup(const BenchmarkConfig& config) = 0;

    /**
     * @brief Run a single benchmark iteration
     * @details Executes the core benchmark logic for one iteration (e.g.,
     *          challenge-proof-verify for PDP, or sign-verify for identity).
     *          After each call, getLastTimings() and getLastMessageSizes()
     *          reflect the metrics from this iteration.
     * @return true if the iteration completed successfully, false on error
     */
    virtual bool runIteration() = 0;

    /**
     * @brief Get the timings from the most recent setup() call
     * @return StageTimings with setup-phase durations
     */
    virtual StageTimings getSetupTimings() const = 0;

    /**
     * @brief Get the timings from the most recent runIteration() call
     * @return StageTimings with iteration-phase durations
     */
    virtual StageTimings getLastTimings() const = 0;

    /**
     * @brief Get the message sizes from the most recent runIteration() call
     * @return MessageSizes with challenge/proof or sign/verify byte counts
     */
    virtual MessageSizes getLastMessageSizes() const = 0;

    /**
     * @brief Clean up resources after benchmarking
     * @details Releases engine, keys, and other resources. After teardown(),
     *          setup() must be called again before runIteration().
     */
    virtual void teardown() = 0;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_SCENARIO_H
