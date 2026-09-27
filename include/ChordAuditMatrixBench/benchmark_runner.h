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
 *          1. validateRun(config, plan) — pre-flight check against the run plan
 *          2. setup(config)    — one-time initialization
 *          3. prepare(config)  — pre-iteration preparation (PDP: corruption)
 *          4. runIteration()   — statically balanced iteration range, each
 *                                iteration followed by recordIteration()
 *          5. teardown()       — cleanup
 *          6. computeResult()  — polymorphic BenchmarkResult
 *          Iterations of one run are partitioned across the effective worker
 *          count of a single BenchmarkRunPlan (config.threads; 0 =
 *          hardware_concurrency, effective count never exceeds iterations).
 *          Worker-local MetricsCollectors are merged on the main thread after
 *          all workers have joined; worker exceptions and validateRun
 *          rejections abort the config without a partial result. A scenario
 *          that cannot partition (supportsParallelIterations() == false, e.g.
 *          the maintenance scenario when no dynamic strategy is resolvable)
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
     * @details Plans the run once (BenchmarkRunPlan: resolved thread request,
     *          effective worker count clamped to the iteration count, balanced
     *          contiguous slot ranges), hands that exact plan to the scenario's
     *          validateRun() before any worker starts, then schedules one
     *          worker per slot. Each worker owns an independently created
     *          scenario and runs setup → prepare → its assigned iterations →
     *          teardown, recording into a worker-local MetricsCollector.
     *          Collectors are merged on the main thread in deterministic slot
     *          order — raw totals/call counts/bytes are summed and averages are
     *          recomputed during result filling. Setup metrics are reported
     *          from worker 0 only: the representative single-setup measurement
     *          of the run. If any worker throws, all threads are joined and the
     *          config fails without a partial result (first failure rethrown);
     *          a validateRun() rejection propagates the same way, before any
     *          worker setup runs.
     * @param config Benchmark configuration
     * @return Polymorphic benchmark result (PdpAuditResult, IdentityResult or
     *         DynamicMaintenanceResult). wallTimeMs is the end-to-end
     *         measurement of the whole lifecycle (setup + prepare + iterations
     *         + teardown), so it is the denominator of any whole-run rate, not
     *         of a single stage.
     */
    std::unique_ptr<BenchmarkResult> runSingle(const BenchmarkConfig& config)
    {
        using Clock = std::chrono::steady_clock;
        const auto wallStart = Clock::now();

        const std::size_t iterations = config.iterations;

        // Worker 0's scenario is created up front: it doubles as the
        // parallel-capability probe and, in the serial path, as the only
        // scenario (identical lifecycle shape to the pre-parallel runner).
        auto worker0Scenario = factory_.createScenario();

        // The plan owns thread resolution, the clamp to the iteration count and
        // the balanced slot ranges; both the scheduling below and the
        // scenario precondition check (validateRun) read this one instance.
        BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(iterations, config.threads);
        if (plan.effectiveThreads() > 1 && !worker0Scenario->supportsParallelIterations()) {
            spdlog::info("  Scenario cannot partition iterations across threads "
                         "— running serially.");
            plan = plan.asSingleWorker();
        }
        // Pre-flight validation against the exact plan that is about to run.
        // A throwing scenario (e.g. Delete capacity smaller than the largest
        // assigned slot) aborts here, before any worker setup.
        worker0Scenario->validateRun(config, plan);
        spdlog::info("  Benchmarking iterations={} (threads: requested={}, effective={}) ...",
                     iterations, plan.requestedThreads(), plan.effectiveThreads());

        const std::size_t effectiveThreads = plan.effectiveThreads();

        // Worker-local collectors and failures live in deterministic indexed
        // slots; only the main thread touches them after every worker joined.
        std::vector<MetricsCollector> workers(effectiveThreads);
        std::vector<std::exception_ptr> failures(effectiveThreads, nullptr);

        // One full scenario lifecycle over the slot's iteration range.
        // Exceptions are captured per slot and the scenario is torn down
        // best-effort before the worker exits.
        auto runWorkerLifecycle = [&](std::size_t slot, MetricsCollector& out,
                                      BenchmarkScenario& scenario) {
            const std::size_t begin = plan.slotBegin(slot);
            const std::size_t count = plan.slotCount(slot);
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
            runWorkerLifecycle(slot, workers[slot], *scenario);
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
        runWorkerLifecycle(0, workers[0], *worker0Scenario);
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
        result->requestedThreads = plan.requestedThreads();
        result->effectiveThreads = effectiveThreads;
        result->wallTimeMs = std::chrono::duration<double, std::milli>(
            Clock::now() - wallStart).count();
        return result;
    }

private:
    BenchmarkScenarioFactory factory_;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_RUNNER_H
