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
 *          polymorphic virtual-method dispatch on BenchmarkScenario instances
 *          produced by an owned BenchmarkScenarioFactory — one scenario per
 *          parallel worker, per run:
 *          1. setup(config)    — one-time initialization
 *          2. prepare(config)  — pre-iteration preparation (PDP: corruption)
 *          3. runIteration()   — statically balanced iteration range, each
 *                                iteration followed by recordIteration()
 *          4. teardown()       — cleanup
 *          5. computeResult()  — polymorphic BenchmarkResult
 *          Iterations of one run are partitioned across the effective worker
 *          count (config.threads; 0 = hardware_concurrency, effective count
 *          never exceeds iterations). Worker-local MetricsCollectors are
 *          merged on the main thread after all workers have joined; worker
 *          exceptions abort the config without a partial result. A scenario
 *          that cannot partition (supportsParallelIterations() == false, e.g.
 *          dynamic PDP with per-run state injected on the shared algorithm)
 *          forces serial execution. Zero type switch — legacy runSweep() and
 *          scenarioKindToResultKind() have been removed (sweep orchestration
 *          now lives in CLI main).
 * @author Dylan Liu
 * @version 4.2.0
 * @date 2026-09-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
#define CAMATRIX_AUDIT_BENCHMARK_RUNNER_H

#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class BenchmarkScenarioFactory
 * @brief OOP scenario factory owned by BenchmarkRunner
 * @details The single creation boundary for benchmark scenarios: the runner
 *          calls createScenario() once per worker per run and receives an
 *          independent scenario instance (own data and RNG state). Concrete
 *          scenario construction is injected as a creator callable, so no
 *          polymorphic factory family is needed — each executable wires the
 *          factory to its concrete scenario (PDP or identity) exactly once.
 */
class BenchmarkScenarioFactory {
public:
    /// @brief Creates one scenario instance of the wired concrete type
    using Creator = std::function<std::unique_ptr<BenchmarkScenario>()>;

    /**
     * @brief Construct a factory from a scenario creator callable
     * @param creator Callable producing fresh scenario instances
     */
    explicit BenchmarkScenarioFactory(Creator creator)
        : creator_(std::move(creator))
    {}

    /**
     * @brief Create a fresh, independent scenario instance
     * @return Owned scenario ready for a full setup→prepare→iterations→teardown lifecycle
     */
    std::unique_ptr<BenchmarkScenario> createScenario() const
    {
        return creator_();
    }

private:
    Creator creator_;
};

/**
 * @class BenchmarkRunner
 * @brief Orchestrates execution of a benchmark scenario for one config
 * @details Owns a BenchmarkScenarioFactory; runSingle() runs the full
 *          lifecycle with pure virtual dispatch — in parallel when the config
 *          requests more than one thread and the scenario supports partition —
 *          and returns a polymorphic BenchmarkResult.
 */
class BenchmarkRunner {
public:
    /**
     * @brief Construct a runner with the given scenario factory
     * @param factory Creates independent scenario instances (one per worker)
     */
    explicit BenchmarkRunner(BenchmarkScenarioFactory factory)
        : factory_(std::move(factory))
    {}

    /**
     * @brief Run benchmark for a single parameter combination
     * @details Splits the iteration range across effective worker threads
     *          (requested threads clamped to the iteration count; 0 requests
     *          hardware_concurrency). Each worker owns an independently
     *          created scenario and runs setup → prepare → its assigned
     *          iterations → teardown, recording into a worker-local
     *          MetricsCollector. Collectors are merged on the main thread in
     *          deterministic slot order — raw totals/call counts/bytes are
     *          summed and averages are recomputed during result filling.
     *          Setup metrics are reported from worker 0 only: the
     *          representative single-setup measurement of the run. If any
     *          worker throws, all threads are joined and the config fails
     *          without a partial result (first failure rethrown).
     * @param config Benchmark configuration
     * @return Polymorphic benchmark result (PdpAuditResult or IdentityResult)
     */
    std::unique_ptr<BenchmarkResult> runSingle(const BenchmarkConfig& config)
    {
        using Clock = std::chrono::steady_clock;
        const auto wallStart = Clock::now();

        const std::size_t iterations = config.iterations;
        const std::size_t requestedThreads = resolveThreadRequest(config.threads);
        // Never split more workers than iterations; a degenerate zero-iteration
        // config still runs one full lifecycle (as the serial runner did).
        std::size_t effectiveThreads = std::min(requestedThreads,
                                                std::max<std::size_t>(iterations, 1));

        // Worker 0's scenario is created up front: it doubles as the
        // parallel-capability probe and, in the serial path, as the only
        // scenario (identical lifecycle shape to the pre-parallel runner).
        auto worker0Scenario = factory_.createScenario();
        if (effectiveThreads > 1 && !worker0Scenario->supportsParallelIterations()) {
            spdlog::info("  Scenario cannot partition iterations across threads "
                         "(shared per-run algorithm state) — running serially.");
            effectiveThreads = 1;
        }
        spdlog::info("  Benchmarking iterations={} (threads: requested={}, effective={}) ...",
                     iterations, requestedThreads, effectiveThreads);

        // Static balanced ranges: worker i runs base + (i < remainder ? 1 : 0)
        // iterations over the contiguous interval [slotBegin(i), +slotCount(i)).
        const std::size_t base = iterations / effectiveThreads;
        const std::size_t remainder = iterations % effectiveThreads;
        const auto slotBegin = [&](std::size_t slot) {
            return slot * base + std::min(slot, remainder);
        };
        const auto slotCount = [&](std::size_t slot) {
            return base + (slot < remainder ? 1 : 0);
        };

        // Worker-local collectors and failures live in deterministic indexed
        // slots; only the main thread touches them after every worker joined.
        std::vector<MetricsCollector> workers(effectiveThreads);
        std::vector<std::exception_ptr> failures(effectiveThreads, nullptr);

        // One full scenario lifecycle over [begin, begin + count) iterations.
        // Exceptions are captured per slot and the scenario is torn down
        // best-effort before the worker exits.
        auto runWorkerLifecycle = [&](std::size_t slot, std::size_t begin,
                                      std::size_t count,
                                      MetricsCollector& out,
                                      BenchmarkScenario& scenario) {
            try {
                scenario.setup(config);
                out.recordSetupTimings(scenario.getSetupTimings());
                out.recordSetupMessageSizes(scenario.getSetupMessageSizes());
                scenario.prepare(config);
                for (std::size_t i = begin; i < begin + count; ++i) {
                    scenario.runIteration();
                    out.recordTimings(scenario.getLastTimings());
                    out.recordMessageSizes(scenario.getLastMessageSizes());
                    scenario.recordIteration(out);
                }
                scenario.teardown();
            } catch (...) {
                try {
                    scenario.teardown();
                } catch (...) {
                }
                failures[slot] = std::current_exception();
            }
        };

        // Pooled workers construct their own independent scenario.
        auto pooledWorker = [&](std::size_t slot) {
            std::unique_ptr<BenchmarkScenario> scenario;
            try {
                scenario = factory_.createScenario();
            } catch (...) {
                failures[slot] = std::current_exception();
                return;
            }
            runWorkerLifecycle(slot, slotBegin(slot), slotCount(slot),
                               workers[slot], *scenario);
        };

        std::vector<std::thread> pool;
        pool.reserve(effectiveThreads - 1);
        try {
            for (std::size_t slot = 1; slot < effectiveThreads; ++slot) {
                pool.emplace_back(pooledWorker, slot);
            }
        } catch (...) {
            // Thread creation failed: join whatever is already running, then
            // fail — never run or merge partial work.
            for (auto& thread : pool) {
                thread.join();
            }
            throw;
        }
        runWorkerLifecycle(0, slotBegin(0), slotCount(0), workers[0], *worker0Scenario);
        for (auto& thread : pool) {
            thread.join();
        }

        // Fail the config without a partial result when any worker failed.
        for (const auto& failure : failures) {
            if (failure) {
                spdlog::error("  A benchmark worker failed — config aborted without result.");
                std::rethrow_exception(failure);
            }
        }

        // Main-thread merge in deterministic slot order. mergeFrom() sums raw
        // totals/call counts/bytes and outcome counters and keeps worker 0's
        // setup record as the representative single-setup measurement;
        // averages are recomputed only when the result is filled below.
        MetricsCollector merged = std::move(workers[0]);
        for (std::size_t slot = 1; slot < effectiveThreads; ++slot) {
            merged.mergeFrom(workers[slot]);
        }

        auto result = worker0Scenario->computeResult(merged, config);
        result->algorithmType = worker0Scenario->algorithmType();
        result->requestedThreads = requestedThreads;
        result->effectiveThreads = effectiveThreads;
        result->wallTimeMs = std::chrono::duration<double, std::milli>(
            Clock::now() - wallStart).count();
        return result;
    }

private:
    /**
     * @brief Resolve the requested worker count
     * @details 0 requests std::thread::hardware_concurrency() with a fallback
     *          of 1 when the hardware count is unavailable; any explicit
     *          request is respected as-is (the caller clamps it to the
     *          iteration count).
     * @param requested Raw --threads value (default 1)
     * @return Resolved thread request
     */
    static std::size_t resolveThreadRequest(std::size_t requested)
    {
        if (requested == 0) {
            const unsigned hw = std::thread::hardware_concurrency();
            requested = (hw > 0) ? static_cast<std::size_t>(hw) : 1;
        }
        return requested;
    }

    BenchmarkScenarioFactory factory_;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
