/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file test_benchmark_run_plan_unit.cpp
 * @brief Tests for BenchmarkRunPlan scheduling and the runner <-> scenario contract.
 * @details Owned by the Bench repository (framework-only, no algorithm plugin):
 *          - the plan owns thread resolution, the clamp to the iteration count
 *            and the balanced contiguous slot ranges;
 *          - the runner hands the exact plan it schedules to
 *            BenchmarkScenario::validateRun() before any worker setup;
 *          - a validateRun() rejection aborts the run before setup;
 *          - the maintenance Delete guard consumes the plan's largest slot, so
 *            the accepted capacity and the executed slot ranges agree.
 */

#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/dynamic_maintenance_scenario.h>

#include <ChordAuditMatrixLib/implementations/audit/in_memory_audit_strategy_manager.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace CAMatrix::Audit::Benchmark {
namespace {

std::size_t resolvedHardwareThreads()
{
    const unsigned hardware = std::thread::hardware_concurrency();
    return (hardware > 0) ? static_cast<std::size_t>(hardware) : 1;
}

// ============================================================================
// Plan math: resolution, clamp and balanced contiguous slots
// ============================================================================

TEST(BenchmarkRunPlanTest, ExplicitRequestKeepsOneSlotPerWorker)
{
    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(10, 4);

    EXPECT_EQ(plan.requestedThreads(), 4U);
    EXPECT_EQ(plan.effectiveThreads(), 4U);
    // 10 iterations over 4 workers: 3 + 3 + 2 + 2.
    EXPECT_EQ(plan.slotCount(0), 3U);
    EXPECT_EQ(plan.slotCount(1), 3U);
    EXPECT_EQ(plan.slotCount(2), 2U);
    EXPECT_EQ(plan.slotCount(3), 2U);
    EXPECT_EQ(plan.slotBegin(0), 0U);
    EXPECT_EQ(plan.slotBegin(1), 3U);
    EXPECT_EQ(plan.slotBegin(2), 6U);
    EXPECT_EQ(plan.slotBegin(3), 8U);
    EXPECT_EQ(plan.largestSlotCount(), 3U);
}

TEST(BenchmarkRunPlanTest, ZeroRequestResolvesHardwareConcurrency)
{
    const std::size_t hardware = resolvedHardwareThreads();
    EXPECT_EQ(BenchmarkRunPlan::resolveThreadRequest(0), hardware);
    EXPECT_EQ(BenchmarkRunPlan::resolveThreadRequest(7), 7U);

    // 5 iterations clamp the resolved hardware count; the request is reported
    // unresolved so the result can show what the user asked for.
    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(5, 0);
    EXPECT_EQ(plan.requestedThreads(), hardware);
    EXPECT_EQ(plan.effectiveThreads(), std::min(hardware, std::size_t{5}));
}

TEST(BenchmarkRunPlanTest, EffectiveWorkersNeverExceedIterations)
{
    // 3 iterations over 8 requested workers: one iteration per worker, and no
    // worker slot is empty.
    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(3, 8);

    EXPECT_EQ(plan.requestedThreads(), 8U);
    EXPECT_EQ(plan.effectiveThreads(), 3U);
    EXPECT_EQ(plan.largestSlotCount(), 1U);
    for (std::size_t slot = 0; slot < plan.effectiveThreads(); ++slot) {
        EXPECT_EQ(plan.slotCount(slot), 1U) << "slot " << slot;
    }
}

TEST(BenchmarkRunPlanTest, ZeroIterationsStillPlanOneSlot)
{
    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(0, 4);

    EXPECT_EQ(plan.requestedThreads(), 4U);
    EXPECT_EQ(plan.effectiveThreads(), 1U);
    EXPECT_EQ(plan.slotCount(0), 0U);
    EXPECT_EQ(plan.largestSlotCount(), 0U);
}

TEST(BenchmarkRunPlanTest, SlotsAreContiguousAndCoverEveryIterationOnce)
{
    for (const std::size_t threads : {1U, 2U, 3U, 4U, 7U}) {
        const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(11, threads);
        std::size_t next = 0;
        std::size_t covered = 0;
        for (std::size_t slot = 0; slot < plan.effectiveThreads(); ++slot) {
            EXPECT_EQ(plan.slotBegin(slot), next) << "threads=" << threads << " slot " << slot;
            EXPECT_LE(plan.slotCount(slot), plan.largestSlotCount());
            covered += plan.slotCount(slot);
            next = plan.slotBegin(slot) + plan.slotCount(slot);
        }
        EXPECT_EQ(covered, 11U) << "threads=" << threads;
        EXPECT_EQ(next, 11U) << "threads=" << threads;
    }
}

TEST(BenchmarkRunPlanTest, SingleWorkerDowngradePreservesRequestAndCoversWholeRange)
{
    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(10, 4).asSingleWorker();

    EXPECT_EQ(plan.requestedThreads(), 4U);
    EXPECT_EQ(plan.effectiveThreads(), 1U);
    EXPECT_EQ(plan.slotBegin(0), 0U);
    EXPECT_EQ(plan.slotCount(0), 10U);
    EXPECT_EQ(plan.largestSlotCount(), 10U);
}

// ============================================================================
// Runner <-> scenario plan contract
// ============================================================================

/// Records the plan handed to validateRun() and whether any setup ran before
/// that call. Iterations are counted per scenario instance.
class PlanProbeScenario final : public BenchmarkScenario {
public:
    struct Shared {
        BenchmarkRunPlan validatedPlan;
        std::atomic<std::size_t> validateCalls{0};
        std::atomic<std::size_t> instances{0};
        std::atomic<std::size_t> setups{0};
        std::atomic<std::size_t> iterations{0};
        std::atomic<std::size_t> setupsBeforeValidation{0};
        std::atomic<bool> reject{false};
    };

    explicit PlanProbeScenario(Shared& shared)
        : shared_(shared)
    {
        shared_.instances.fetch_add(1);
    }

    std::string algorithmType() const override { return "PlanProbe"; }

    void validateRun(const BenchmarkConfig& /*config*/,
                     const BenchmarkRunPlan& plan) override
    {
        if (shared_.validateCalls.fetch_add(1) == 0) {
            shared_.validatedPlan = plan;
        }
        if (shared_.reject.load()) {
            throw std::invalid_argument("PlanProbeScenario: rejected by validateRun");
        }
    }

    void setup(const BenchmarkConfig& /*config*/) override
    {
        shared_.setups.fetch_add(1);
        if (shared_.validateCalls.load() == 0) {
            shared_.setupsBeforeValidation.fetch_add(1);
        }
    }

    void runIteration() override { shared_.iterations.fetch_add(1); }

    void recordIteration(MetricsCollector& collector) override
    {
        collector.recordOutcome(true, "");
    }

    std::unique_ptr<BenchmarkResult> computeResult(const MetricsCollector& collector,
                                                   const BenchmarkConfig& config) override
    {
        auto result = std::make_unique<PdpAuditResult>();
        collector.fillPdpResult(*result, static_cast<const PdpAuditConfig&>(config));
        return result;
    }

    StageTimings getSetupTimings() const override { return {}; }
    StageTimings getLastTimings() const override { return {}; }
    void teardown() override {}

private:
    Shared& shared_;
};

std::unique_ptr<BenchmarkResult> runProbe(PlanProbeScenario::Shared& shared,
                                          std::size_t iterations, std::size_t threads)
{
    BenchmarkRunner runner(BenchmarkScenarioFactory([&shared] {
        return std::make_unique<PlanProbeScenario>(shared);
    }));
    PdpAuditConfig config;
    config.iterations = iterations;
    config.threads = threads;
    return runner.runSingle(config);
}

TEST(BenchmarkRunnerPlanTest, ValidatesExactlyThePlanItExecutes)
{
    PlanProbeScenario::Shared shared;
    auto raw = runProbe(shared, 10, 4);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const PdpAuditResult&>(*raw);

    // One validation, before any worker setup, reporting the executed schedule.
    EXPECT_EQ(shared.validateCalls.load(), 1U);
    EXPECT_EQ(shared.setupsBeforeValidation.load(), 0U);
    EXPECT_EQ(shared.validatedPlan.effectiveThreads(), result.effectiveThreads);
    EXPECT_EQ(shared.validatedPlan.requestedThreads(), result.requestedThreads);
    EXPECT_EQ(shared.validatedPlan.effectiveThreads(), 4U);
    // The plan's slots sum to the global iteration count that actually ran.
    std::size_t planned = 0;
    for (std::size_t slot = 0; slot < shared.validatedPlan.effectiveThreads(); ++slot) {
        planned += shared.validatedPlan.slotCount(slot);
    }
    EXPECT_EQ(planned, 10U);
    EXPECT_EQ(shared.iterations.load(), 10U);
    EXPECT_EQ(result.detections, 10U);
}

TEST(BenchmarkRunnerPlanTest, ValidatesBeforeEveryWorkerSetupAndSplitsEvenly)
{
    PlanProbeScenario::Shared shared;
    runProbe(shared, 4, 2);

    EXPECT_EQ(shared.instances.load(), 2U);
    EXPECT_EQ(shared.setups.load(), 2U);
    EXPECT_EQ(shared.iterations.load(), 4U);
    EXPECT_EQ(shared.validatedPlan.effectiveThreads(), 2U);
    EXPECT_EQ(shared.validatedPlan.slotCount(0), 2U);
    EXPECT_EQ(shared.validatedPlan.slotCount(1), 2U);
}

TEST(BenchmarkRunnerPlanTest, ValidationRejectionAbortsBeforeAnySetup)
{
    PlanProbeScenario::Shared shared;
    shared.reject.store(true);

    EXPECT_THROW(runProbe(shared, 6, 2), std::invalid_argument);

    // The probe scenario is created up front, but the rejection happens before
    // any worker lifecycle starts: no setup, no iteration.
    EXPECT_EQ(shared.validateCalls.load(), 1U);
    EXPECT_EQ(shared.setups.load(), 0U);
    EXPECT_EQ(shared.iterations.load(), 0U);
}

// ============================================================================
// Delete capacity guard agrees with the plan's slot ranges
// ============================================================================

DynamicMaintenanceConfig makeDeleteConfig(std::size_t initialBlocks,
                                          std::size_t iterations,
                                          std::size_t threads)
{
    DynamicMaintenanceConfig config;
    config.operation = MaintenanceOperation::Delete;
    config.initialBlocks = initialBlocks;
    config.iterations = iterations;
    config.threads = threads;
    return config;
}

TEST(DynamicMaintenanceRunPlanGuardTest, DeleteCapacityIsCheckedAgainstLargestSlot)
{
    // No plugin needed: validateRun() is a pure config/plan precondition check.
    auto manager = std::make_shared<CAMatrix::Audit::Loader::InMemoryAuditStrategyManager>();
    DynamicMaintenanceScenario scenario("DHTDynamic", manager);

    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(10, 4);
    ASSERT_EQ(plan.effectiveThreads(), 4U);
    ASSERT_EQ(plan.largestSlotCount(), 3U);

    // Exactly the largest slot is enough; one block less is rejected.
    EXPECT_NO_THROW(scenario.validateRun(makeDeleteConfig(3, 10, 4), plan));
    EXPECT_THROW(scenario.validateRun(makeDeleteConfig(2, 10, 4), plan),
                 std::invalid_argument);
}

TEST(DynamicMaintenanceRunPlanGuardTest, NonDeleteOperationsIgnoreWorkerCapacity)
{
    auto manager = std::make_shared<CAMatrix::Audit::Loader::InMemoryAuditStrategyManager>();
    DynamicMaintenanceScenario scenario("DHTDynamic", manager);

    const BenchmarkRunPlan plan = BenchmarkRunPlan::balanced(10, 4);
    const auto update = [&] {
        DynamicMaintenanceConfig config = makeDeleteConfig(1, 10, 4);
        config.operation = MaintenanceOperation::Update;
        return config;
    }();
    const auto insert = [&] {
        DynamicMaintenanceConfig config = makeDeleteConfig(1, 10, 4);
        config.operation = MaintenanceOperation::Insert;
        return config;
    }();

    EXPECT_NO_THROW(scenario.validateRun(update, plan));
    EXPECT_NO_THROW(scenario.validateRun(insert, plan));
}

TEST(DynamicMaintenanceRunPlanGuardTest, RunnerGuardsDeleteCapacityFromThePlan)
{
    // A manager without the algorithm resolves no strategy, so the run stays
    // serial: the schedule is one slot over all 10 iterations and the guard
    // still consumes the plan it was handed instead of re-deriving a thread
    // count. One block short of that slot is rejected. That the rejection
    // happens before any worker setup is covered structurally by
    // BenchmarkRunnerPlanTest.ValidationRejectionAbortsBeforeAnySetup, and the
    // capacity-covering case is covered by the validateRun test above plus the
    // parent repository's real-strategy integration run.
    auto manager = std::make_shared<CAMatrix::Audit::Loader::InMemoryAuditStrategyManager>();
    BenchmarkRunner runner(BenchmarkScenarioFactory([manager] {
        return std::make_unique<DynamicMaintenanceScenario>("DHTDynamic", manager);
    }));

    EXPECT_THROW(runner.runSingle(makeDeleteConfig(9, 10, 4)), std::invalid_argument);
}

} // namespace
} // namespace CAMatrix::Audit::Benchmark
