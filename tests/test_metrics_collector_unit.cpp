/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file test_metrics_collector_unit.cpp
 * @brief Regression tests for benchmark outcome aggregation and runner scheduling.
 * @details Owned by the Bench repository: these tests exercise only the
 *          benchmark framework (MetricsCollector aggregation, the runner's
 *          BenchmarkRunPlan scheduling and worker isolation) and link no
 *          algorithm plugin, so they build and run wherever Bench builds.
 */

#include "ChordAuditMatrixBench/benchmark_runner.h"
#include "ChordAuditMatrixBench/metrics_collector.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace CAMatrix::Audit::Benchmark {
namespace {

TEST(MetricsCollectorTest, IdentityOutcomeAveragesUseConfiguredIterations)
{
    MetricsCollector collector;
    IdentityConfig config;
    config.iterations = 4;

    for (std::size_t i = 0; i < config.iterations; ++i) {
        collector.recordIdentityOutcome(true, true);   // TP
        collector.recordIdentityOutcome(true, true);   // TP
        collector.recordIdentityOutcome(true, false);  // FP
        collector.recordIdentityOutcome(false, false); // TN
        collector.recordIdentityOutcome(false, false); // TN
        collector.recordIdentityOutcome(false, false); // TN
    }

    IdentityResult result;
    collector.fillIdentityResult(result, config);

    EXPECT_EQ(result.totalVerifySamples, 24U);
    EXPECT_DOUBLE_EQ(result.averageVerifySamples, 6.0);
    EXPECT_DOUBLE_EQ(result.accuracyRate, 20.0 / 24.0);
    EXPECT_EQ(result.trueAccepts, 8U);
    EXPECT_EQ(result.falseAccepts, 4U);
    EXPECT_EQ(result.trueRejects, 12U);
    EXPECT_EQ(result.falseRejects, 0U);
    EXPECT_DOUBLE_EQ(result.averageTrueAccepts, 2.0);
    EXPECT_DOUBLE_EQ(result.averageFalseAccepts, 1.0);
    EXPECT_DOUBLE_EQ(result.averageTrueRejects, 3.0);
    EXPECT_DOUBLE_EQ(result.averageFalseRejects, 0.0);
}

TEST(MetricsCollectorTest, IdentityOutcomeAveragesPreserveFractionalCounts)
{
    MetricsCollector collector;
    IdentityConfig config;
    config.iterations = 3;

    collector.recordIdentityOutcome(true, true);

    IdentityResult result;
    collector.fillIdentityResult(result, config);

    EXPECT_EQ(result.totalVerifySamples, 1U);
    EXPECT_DOUBLE_EQ(result.averageVerifySamples, 1.0 / 3.0);
    EXPECT_DOUBLE_EQ(result.averageTrueAccepts, 1.0 / 3.0);
    EXPECT_DOUBLE_EQ(result.averageFalseAccepts, 0.0);
    EXPECT_DOUBLE_EQ(result.averageTrueRejects, 0.0);
    EXPECT_DOUBLE_EQ(result.averageFalseRejects, 0.0);
}

TEST(MetricsCollectorTest, PdpDetectionsRemainTotalWithNormalizedConfidenceRate)
{
    MetricsCollector collector;
    PdpAuditConfig config;
    config.iterations = 4;

    collector.recordOutcome(true, "detected");
    collector.recordOutcome(true, "detected");
    collector.recordOutcome(true, "detected");
    collector.recordOutcome(false, "not detected");

    PdpAuditResult result;
    collector.fillPdpResult(result, config);

    EXPECT_EQ(result.detections, 3U);
    EXPECT_DOUBLE_EQ(result.confidenceRate, 0.75);
}

TEST(MetricsCollectorTest, MaintenanceOutcomesSplitIntoSucceededAndFailedCounts)
{
    MetricsCollector collector;
    DynamicMaintenanceConfig config;
    config.iterations = 4;
    config.initialBlocks = 3;
    config.operation = MaintenanceOperation::Delete;

    collector.recordMaintenanceOutcome(true);
    collector.recordMaintenanceOutcome(true);
    collector.recordMaintenanceOutcome(false);
    collector.recordMaintenanceOutcome(true);

    DynamicMaintenanceResult result;
    collector.fillDynamicMaintenanceResult(result, config);

    EXPECT_EQ(result.operation, MaintenanceOperation::Delete);
    EXPECT_EQ(result.initialBlocks, 3U);
    EXPECT_EQ(result.iterations, 4U);
    EXPECT_EQ(result.successfulOperations, 3U);
    EXPECT_EQ(result.failedOperations, 1U);

    // A reset collector starts from zero on both halves of the call total.
    collector.reset();
    DynamicMaintenanceResult cleared;
    collector.fillDynamicMaintenanceResult(cleared, config);
    EXPECT_EQ(cleared.successfulOperations, 0U);
    EXPECT_EQ(cleared.failedOperations, 0U);
}

// ============================================================================
// MetricsCollector::mergeFrom — raw totals/averages across worker collectors
// ============================================================================

TEST(MetricsCollectorMergeTest, MergedIdentityOutcomeCountersSumAndRecomputeAverages)
{
    MetricsCollector workerA;
    workerA.recordIdentityOutcome(true, true);    // TP
    workerA.recordIdentityOutcome(true, true);    // TP
    workerA.recordIdentityOutcome(true, false);   // FP
    workerA.recordIdentityOutcome(false, false);  // TN
    workerA.recordIdentityOutcome(false, false);  // TN
    workerA.recordIdentityOutcome(false, false);  // TN

    MetricsCollector workerB;
    workerB.recordIdentityOutcome(false, false);  // TN
    workerB.recordIdentityOutcome(false, true);   // FN

    workerA.mergeFrom(workerB);

    IdentityConfig config;
    config.iterations = 4;  // whole-run iteration count; fill divides by it
    IdentityResult result;
    workerA.fillIdentityResult(result, config);

    // Raw outcome counters are summed, never averaged per worker.
    EXPECT_EQ(result.totalVerifySamples, 8U);
    EXPECT_EQ(result.trueAccepts, 2U);
    EXPECT_EQ(result.falseAccepts, 1U);
    EXPECT_EQ(result.trueRejects, 4U);
    EXPECT_EQ(result.falseRejects, 1U);
    EXPECT_DOUBLE_EQ(result.accuracyRate, 6.0 / 8.0);
    // Averages are derived from the merged totals at fill time.
    EXPECT_DOUBLE_EQ(result.averageVerifySamples, 2.0);
    EXPECT_DOUBLE_EQ(result.averageTrueAccepts, 0.5);
    EXPECT_DOUBLE_EQ(result.averageFalseAccepts, 0.25);
    EXPECT_DOUBLE_EQ(result.averageTrueRejects, 1.0);
    EXPECT_DOUBLE_EQ(result.averageFalseRejects, 0.25);
}

TEST(MetricsCollectorMergeTest, MergedPdpAndIterationMetricsSumRawTotals)
{
    MetricsCollector workerA;
    StageTimings timingsA;
    timingsA.verifyProofs.totalMs = 30.0;  // average 10.0
    timingsA.verifyProofs.callCount = 3;
    timingsA.sign.totalMs = 6.0;           // present in worker A only
    timingsA.sign.callCount = 3;
    workerA.recordTimings(timingsA);
    MessageSizes sizesA;
    sizesA.proof.totalBytes = 120;         // average 60.0
    sizesA.proof.messageCount = 2;
    workerA.recordMessageSizes(sizesA);
    workerA.recordOutcome(true, "detected");
    workerA.recordOutcome(true, "detected");
    workerA.recordOutcome(false, "missed");
    workerA.setMemoryPeak(64);

    MetricsCollector workerB;
    StageTimings timingsB;
    timingsB.verifyProofs.totalMs = 10.0;  // average 5.0
    timingsB.verifyProofs.callCount = 2;
    workerB.recordTimings(timingsB);
    MessageSizes sizesB;
    sizesB.proof.totalBytes = 60;          // average 20.0
    sizesB.proof.messageCount = 3;
    sizesB.keyGeneration.totalBytes = 45;  // present in worker B only
    sizesB.keyGeneration.messageCount = 3;
    workerB.recordMessageSizes(sizesB);
    workerB.recordOutcome(true, "detected");
    workerB.recordOutcome(false, "missed");
    workerB.recordOutcome(false, "missed");
    workerB.setMemoryPeak(128);

    workerA.mergeFrom(workerB);

    PdpAuditConfig config;
    config.iterations = 6;  // 3 + 3 executed iterations
    PdpAuditResult result;
    workerA.fillPdpResult(result, config);

    EXPECT_EQ(result.detections, 3U);
    EXPECT_DOUBLE_EQ(result.confidenceRate, 3.0 / 6.0);
    // Raw totals/call counts sum; the average is recomputed from the merged
    // totals (averaging the per-worker averages would give 7.5, not 8.0).
    EXPECT_DOUBLE_EQ(result.iterationTimings.verifyProofs.totalMs, 40.0);
    EXPECT_EQ(result.iterationTimings.verifyProofs.callCount, 5U);
    EXPECT_DOUBLE_EQ(result.iterationTimings.verifyProofs.averageMs, 8.0);
    // Stages recorded by a single worker survive the merge untouched.
    EXPECT_DOUBLE_EQ(result.iterationTimings.sign.totalMs, 6.0);
    EXPECT_EQ(result.iterationTimings.sign.callCount, 3U);
    EXPECT_DOUBLE_EQ(result.iterationTimings.sign.averageMs, 2.0);
    // Same raw-sum/average-recompute contract for message sizes.
    EXPECT_EQ(result.iterationMessageSizes.proof.totalBytes, 180U);
    EXPECT_EQ(result.iterationMessageSizes.proof.messageCount, 5U);
    EXPECT_DOUBLE_EQ(result.iterationMessageSizes.proof.averageBytes, 36.0);
    EXPECT_EQ(result.iterationMessageSizes.keyGeneration.totalBytes, 45U);
    EXPECT_EQ(result.iterationMessageSizes.keyGeneration.messageCount, 3U);
    EXPECT_DOUBLE_EQ(result.iterationMessageSizes.keyGeneration.averageBytes, 15.0);
    // Memory peak takes the higher of the two workers.
    EXPECT_EQ(result.memoryPeakBytes, 128U);
}

TEST(MetricsCollectorMergeTest, MergedMaintenanceOutcomesAndCallTimingsSumAcrossWorkers)
{
    MetricsCollector workerA;
    StageTimings timingsA;
    timingsA.maintain.totalMs = 30.0;  // 3 calls, per-worker average 10.0
    timingsA.maintain.callCount = 3;
    workerA.recordTimings(timingsA);
    workerA.recordMaintenanceOutcome(true);
    workerA.recordMaintenanceOutcome(true);
    workerA.recordMaintenanceOutcome(false);

    MetricsCollector workerB;
    StageTimings timingsB;
    timingsB.maintain.totalMs = 45.0;  // 2 calls, per-worker average 22.5
    timingsB.maintain.callCount = 2;
    workerB.recordTimings(timingsB);
    workerB.recordMaintenanceOutcome(true);
    workerB.recordMaintenanceOutcome(false);

    workerA.mergeFrom(workerB);

    DynamicMaintenanceConfig config;
    config.iterations = 5;  // 3 + 2 executed maintenance calls
    config.initialBlocks = 2;
    config.operation = MaintenanceOperation::Insert;
    DynamicMaintenanceResult result;
    workerA.fillDynamicMaintenanceResult(result, config);

    EXPECT_EQ(result.operation, MaintenanceOperation::Insert);
    EXPECT_EQ(result.initialBlocks, 2U);
    EXPECT_EQ(result.iterations, 5U);
    EXPECT_EQ(result.successfulOperations, 3U);
    EXPECT_EQ(result.failedOperations, 2U);
    // Raw maintenance totals/call counts sum and the average is recomputed from
    // the merged totals: 75.0 / 5 = 15.0, not the mean of the per-worker
    // averages (10.0 + 22.5) / 2 = 16.25.
    EXPECT_DOUBLE_EQ(result.iterationTimings.maintain.totalMs, 75.0);
    EXPECT_EQ(result.iterationTimings.maintain.callCount, 5U);
    EXPECT_DOUBLE_EQ(result.iterationTimings.maintain.averageMs, 15.0);
}

TEST(MetricsCollectorMergeTest, MergedFinalBlockCountsKeepLatestPerWorkerAndSumAcrossWorkers)
{
    MetricsCollector workerA;
    workerA.recordWorkerFinalBlockCount(9);  // overwritten by the next call:
    workerA.recordWorkerFinalBlockCount(2);  // worker A's final store size
    MetricsCollector workerB;
    workerB.recordWorkerFinalBlockCount(3);  // worker B's final store size

    workerA.mergeFrom(workerB);

    DynamicMaintenanceConfig config;
    config.iterations = 5;
    config.initialBlocks = 4;
    config.operation = MaintenanceOperation::Delete;
    DynamicMaintenanceResult result;
    workerA.fillDynamicMaintenanceResult(result, config);

    // Each worker reports its own latest count (not an accumulated sequence);
    // the merge sums the per-worker counts into the run total: 2 + 3 = 5.
    EXPECT_EQ(result.finalBlocksAcrossWorkerStores, 5U);
    EXPECT_EQ(workerA.workerFinalBlockCount(), 5U);

    // A reset collector drops the recorded worker store size again.
    workerA.reset();
    DynamicMaintenanceResult cleared;
    workerA.fillDynamicMaintenanceResult(cleared, config);
    EXPECT_EQ(cleared.finalBlocksAcrossWorkerStores, 0U);
    EXPECT_EQ(workerA.workerFinalBlockCount(), 0U);
}

TEST(MetricsCollectorMergeTest, MergedSetupTimingsSumRawTotalsAndRecomputeWeightedAverage)
{
    MetricsCollector receiver;
    StageTimings setupA;
    setupA.generateKeys.totalMs = 9.0;
    setupA.generateKeys.callCount = 3;  // per-worker average 3.0
    setupA.sign.totalMs = 7.5;          // recorded by worker A only
    setupA.sign.callCount = 3;          // per-worker average 2.5
    receiver.recordSetupTimings(setupA);
    receiver.setMemoryPeak(256);

    MetricsCollector donor;
    StageTimings setupB;
    setupB.generateKeys.totalMs = 99.0;
    setupB.generateKeys.callCount = 1;  // per-worker average 99.0
    donor.recordSetupTimings(setupB);
    donor.setMemoryPeak(128);

    receiver.mergeFrom(donor);

    PdpAuditResult result;
    receiver.fillPdpResult(result, PdpAuditConfig{});

    // Raw setup totals/call counts sum across every worker's one-time setup;
    // averages are recomputed from the merged totals. The stage recorded by a
    // single worker survives the merge untouched.
    EXPECT_DOUBLE_EQ(result.setupTimings.generateKeys.totalMs, 108.0);
    EXPECT_EQ(result.setupTimings.generateKeys.callCount, 4U);
    EXPECT_DOUBLE_EQ(result.setupTimings.generateKeys.averageMs, 27.0);
    // A setup stage recorded by a single worker survives the merge untouched.
    EXPECT_DOUBLE_EQ(result.setupTimings.sign.totalMs, 7.5);
    EXPECT_EQ(result.setupTimings.sign.callCount, 3U);
    EXPECT_DOUBLE_EQ(result.setupTimings.sign.averageMs, 2.5);
    // Memory peak takes the higher of the two workers.
    EXPECT_EQ(result.memoryPeakBytes, 256U);
}

TEST(MetricsCollectorMergeTest, MergedSetupMessageSizesSumRawBytesAndRecomputeWeightedAverage)
{
    MetricsCollector receiver;
    MessageSizes setupSizesA;
    setupSizesA.tags.totalBytes = 120;
    setupSizesA.tags.messageCount = 2;  // per-worker average 60.0
    setupSizesA.keyGeneration.totalBytes = 81;
    setupSizesA.keyGeneration.messageCount = 9;  // per-worker average 9.0
    setupSizesA.challenge.totalBytes = 40;  // recorded by worker A only
    setupSizesA.challenge.messageCount = 1;
    receiver.recordSetupMessageSizes(setupSizesA);

    MetricsCollector donor;
    MessageSizes setupSizesB;
    setupSizesB.tags.totalBytes = 60;
    setupSizesB.tags.messageCount = 3;  // per-worker average 20.0
    donor.recordSetupMessageSizes(setupSizesB);

    receiver.mergeFrom(donor);

    PdpAuditResult result;
    receiver.fillPdpResult(result, PdpAuditConfig{});

    // Raw setup byte/message counts sum across every worker's one-time setup
    // and the average is recomputed from the merged totals: tags
    // (120 + 60) / 5 = 36.0 is weighted by message count — not the mean of the
    // per-worker averages ((60.0 + 20.0) / 2 = 40.0).
    EXPECT_EQ(result.setupMessageSizes.tags.totalBytes, 180U);
    EXPECT_EQ(result.setupMessageSizes.tags.messageCount, 5U);
    EXPECT_DOUBLE_EQ(result.setupMessageSizes.tags.averageBytes, 36.0);
    // A setup channel recorded by a single worker survives the merge untouched.
    EXPECT_EQ(result.setupMessageSizes.keyGeneration.totalBytes, 81U);
    EXPECT_EQ(result.setupMessageSizes.keyGeneration.messageCount, 9U);
    EXPECT_DOUBLE_EQ(result.setupMessageSizes.keyGeneration.averageBytes, 9.0);
    EXPECT_EQ(result.setupMessageSizes.challenge.totalBytes, 40U);
    EXPECT_EQ(result.setupMessageSizes.challenge.messageCount, 1U);
    EXPECT_DOUBLE_EQ(result.setupMessageSizes.challenge.averageBytes, 40.0);
}

TEST(MetricsCollectorMergeTest, MergeAdoptsDonorSetupRecordWhenReceiverRecordedNone)
{
    MetricsCollector receiver;  // never recorded setup data
    MetricsCollector donor;
    StageTimings setup;
    setup.initAlgorithm.totalMs = 5.0;
    setup.initAlgorithm.callCount = 2;  // average 2.5
    donor.recordSetupTimings(setup);
    MessageSizes sizes;
    sizes.proof.totalBytes = 42;
    sizes.proof.messageCount = 3;  // average 14.0
    donor.recordSetupMessageSizes(sizes);

    receiver.mergeFrom(donor);

    // A receiver without a setup record adopts the donor's full record rather
    // than dropping it. The recorded flag is set by the merge, so a later
    // recordSetup* call is ignored like on any already-recorded collector.
    StageTimings late;
    late.initAlgorithm.totalMs = 999.0;
    late.initAlgorithm.callCount = 1;
    receiver.recordSetupTimings(late);
    MessageSizes lateSizes;
    lateSizes.proof.totalBytes = 999;
    lateSizes.proof.messageCount = 1;
    receiver.recordSetupMessageSizes(lateSizes);

    PdpAuditResult result;
    receiver.fillPdpResult(result, PdpAuditConfig{});
    EXPECT_DOUBLE_EQ(result.setupTimings.initAlgorithm.totalMs, 5.0);
    EXPECT_EQ(result.setupTimings.initAlgorithm.callCount, 2U);
    EXPECT_DOUBLE_EQ(result.setupTimings.initAlgorithm.averageMs, 2.5);
    EXPECT_EQ(result.setupMessageSizes.proof.totalBytes, 42U);
    EXPECT_EQ(result.setupMessageSizes.proof.messageCount, 3U);
    EXPECT_DOUBLE_EQ(result.setupMessageSizes.proof.averageBytes, 14.0);
}

TEST(MetricsCollectorMergeTest, MergeWithoutSetupDataKeepsReceiverRecordAndRecordedFlags)
{
    // A donor without setup data leaves the receiver's setup record intact and
    // cannot clear its recorded flag: a later recordSetup is still ignored.
    MetricsCollector receiver;
    StageTimings setup;
    setup.aggregate.totalMs = 30.0;
    setup.aggregate.callCount = 6;  // average 5.0
    receiver.recordSetupTimings(setup);
    receiver.setMemoryPeak(256);
    receiver.mergeFrom(MetricsCollector{});
    StageTimings late;
    late.aggregate.totalMs = 777.0;
    late.aggregate.callCount = 1;
    receiver.recordSetupTimings(late);

    PdpAuditResult result;
    receiver.fillPdpResult(result, PdpAuditConfig{});
    EXPECT_DOUBLE_EQ(result.setupTimings.aggregate.totalMs, 30.0);
    EXPECT_EQ(result.setupTimings.aggregate.callCount, 6U);
    EXPECT_DOUBLE_EQ(result.setupTimings.aggregate.averageMs, 5.0);
    EXPECT_EQ(result.memoryPeakBytes, 256U);

    // When neither side recorded setup data, the merged collector stays
    // unrecorded: its first recordSetup call afterwards is still accepted.
    MetricsCollector emptyReceiver;
    emptyReceiver.mergeFrom(MetricsCollector{});
    StageTimings first;
    first.aggregateVerify.totalMs = 8.0;
    first.aggregateVerify.callCount = 4;  // average 2.0
    emptyReceiver.recordSetupTimings(first);
    PdpAuditResult emptyResult;
    emptyReceiver.fillPdpResult(emptyResult, PdpAuditConfig{});
    EXPECT_DOUBLE_EQ(emptyResult.setupTimings.aggregateVerify.totalMs, 8.0);
    EXPECT_EQ(emptyResult.setupTimings.aggregateVerify.callCount, 4U);
    EXPECT_DOUBLE_EQ(emptyResult.setupTimings.aggregateVerify.averageMs, 2.0);
}

// ============================================================================
// Deterministic fakes for BenchmarkRunner scheduling/isolation tests
// ----------------------------------------------------------------------------
// FakeBenchmarkScenario records every lifecycle/iteration event into a shared
// atomics-only state, so after all workers have joined the tests can assert:
//   * the runner validated exactly one plan before any worker setup,
//   * every requested iteration executed exactly once,
//   * each worker executed exactly one balanced slot from that plan on a
//     distinct scenario (per-instance iteration counts are the plan's slot
//     sizes; one setup/teardown each, never two workers on one instance),
//   * exactly one scenario instance per effective worker was created.
// No timing measurements, real algorithms, or plugins are involved.
// ============================================================================

class FakeScenarioSharedState {
public:
    struct InstanceCell {
        std::atomic<std::size_t> iterations{0};
        std::atomic<std::size_t> setups{0};
        std::atomic<std::size_t> teardowns{0};
        std::atomic<std::size_t> setupsBeforeValidation{0};
    };

    // Fixed-size cells: std::atomic members make cells non-movable, so they
    // cannot live in a std::vector (C++17 vector growth needs MoveInsertable).
    // One cell per scenario instance; every test below creates far fewer than
    // this bound (created instances <= effective threads <= iterations).
    static constexpr std::size_t kMaxInstances = 64;

    std::atomic<std::size_t> nextInstanceId{0};
    std::atomic<std::size_t> totalIterations{0};
    std::atomic<std::size_t> validateCalls{0};
    std::array<InstanceCell, kMaxInstances> instances;

    /// Plan handed to the first validateRun() call: written on the main thread
    /// before any worker starts, read by the test after every worker joined.
    BenchmarkRunPlan validatedPlan;
};

class FakeBenchmarkScenario final : public BenchmarkScenario {
public:
    FakeBenchmarkScenario(FakeScenarioSharedState& state, std::size_t instanceId,
                          bool supportsParallel)
        : state_(state)
        , instanceId_(instanceId)
        , supportsParallel_(supportsParallel)
    {}

    bool supportsParallelIterations() const override { return supportsParallel_; }
    std::string algorithmType() const override { return "Fake"; }

    void validateRun(const BenchmarkConfig& /*config*/,
                     const BenchmarkRunPlan& plan) override
    {
        if (state_.validateCalls.fetch_add(1) == 0) {
            state_.validatedPlan = plan;
        }
    }

    void setup(const BenchmarkConfig& /*config*/) override
    {
        if (instanceId_ < state_.instances.size()) {
            auto& cell = state_.instances[instanceId_];
            cell.setups.fetch_add(1);
            if (state_.validateCalls.load() == 0) {
                cell.setupsBeforeValidation.fetch_add(1);
            }
        }
    }

    void runIteration() override
    {
        state_.totalIterations.fetch_add(1);
        if (instanceId_ < state_.instances.size()) {
            state_.instances[instanceId_].iterations.fetch_add(1);
        }
    }

    void recordIteration(MetricsCollector& collector) override
    {
        collector.recordIdentityOutcome(true, true);  // one TP per iteration
    }

    std::unique_ptr<BenchmarkResult> computeResult(const MetricsCollector& collector,
                                                   const BenchmarkConfig& config) override
    {
        const auto& identityConfig = static_cast<const IdentityConfig&>(config);
        auto result = std::make_unique<IdentityResult>();
        result->numUsers = identityConfig.numUsers;
        result->algorithmKind = "Fake";
        collector.fillIdentityResult(*result, identityConfig);
        return result;
    }

    StageTimings getSetupTimings() const override
    {
        StageTimings timings;
        timings.generateKeys.totalMs = static_cast<double>(instanceId_ + 1);
        timings.generateKeys.callCount = 1;
        return timings;
    }

    MessageSizes getSetupMessageSizes() const override
    {
        MessageSizes sizes;
        sizes.keyGeneration.totalBytes = 1000 + instanceId_;
        sizes.keyGeneration.messageCount = 1;
        return sizes;
    }

    StageTimings getLastTimings() const override
    {
        StageTimings timings;
        timings.sign.totalMs = 1.0;  // one canned timing record per iteration
        timings.sign.callCount = 1;
        return timings;
    }

    MessageSizes getLastMessageSizes() const override
    {
        MessageSizes sizes;
        sizes.verification.totalBytes = 7;  // one canned message record per iteration
        sizes.verification.messageCount = 1;
        return sizes;
    }

    void teardown() override
    {
        if (instanceId_ < state_.instances.size()) {
            state_.instances[instanceId_].teardowns.fetch_add(1);
        }
    }

private:
    FakeScenarioSharedState& state_;
    const std::size_t instanceId_;
    const bool supportsParallel_;
};

BenchmarkScenarioFactory makeFakeScenarioFactory(FakeScenarioSharedState& state,
                                                 bool supportsParallel)
{
    return BenchmarkScenarioFactory([&state, supportsParallel] {
        const std::size_t instanceId = state.nextInstanceId.fetch_add(1);
        return std::unique_ptr<BenchmarkScenario>(
            new FakeBenchmarkScenario(state, instanceId, supportsParallel));
    });
}

std::unique_ptr<BenchmarkResult> runFakeBenchmark(FakeScenarioSharedState& state,
                                                  std::size_t iterations,
                                                  std::size_t threads,
                                                  bool supportsParallel = true)
{
    BenchmarkRunner runner(makeFakeScenarioFactory(state, supportsParallel));

    IdentityConfig config;
    config.iterations = iterations;
    config.threads = threads;
    config.numUsers = 17;
    return runner.runSingle(config);
}

void expectPlanRanges(const BenchmarkRunPlan& plan)
{
    // The plan's slots are contiguous, non-overlapping and cover the whole
    // iteration range exactly once.
    std::size_t next = 0;
    for (std::size_t slot = 0; slot < plan.effectiveThreads(); ++slot) {
        EXPECT_EQ(plan.slotBegin(slot), next) << "slot " << slot << " begin";
        EXPECT_LE(plan.slotCount(slot), plan.largestSlotCount())
            << "slot " << slot << " larger than the largest slot";
        next += plan.slotCount(slot);
    }
    EXPECT_EQ(next, plan.slotBegin(plan.effectiveThreads()));
}

void expectFullRunRecorded(const BenchmarkResult& result, std::size_t iterations)
{
    const auto& identity = static_cast<const IdentityResult&>(result);
    EXPECT_EQ(identity.iterations, iterations);
    EXPECT_EQ(identity.numUsers, 17U);
    // One TP sample recorded per iteration, merged across all workers.
    EXPECT_EQ(identity.totalVerifySamples, iterations);
    EXPECT_EQ(identity.trueAccepts, iterations);
    EXPECT_EQ(identity.falseAccepts, 0U);
    EXPECT_EQ(identity.trueRejects, 0U);
    EXPECT_EQ(identity.falseRejects, 0U);
    EXPECT_DOUBLE_EQ(identity.averageVerifySamples, 1.0);
    EXPECT_DOUBLE_EQ(identity.accuracyRate, 1.0);
    // One canned timing/message record per iteration, summed over workers.
    EXPECT_DOUBLE_EQ(identity.iterationTimings.sign.totalMs,
                     static_cast<double>(iterations));
    EXPECT_EQ(identity.iterationTimings.sign.callCount, iterations);
    EXPECT_DOUBLE_EQ(identity.iterationTimings.sign.averageMs, 1.0);
    EXPECT_EQ(identity.iterationMessageSizes.verification.totalBytes, 7U * iterations);
    EXPECT_EQ(identity.iterationMessageSizes.verification.messageCount, iterations);
    EXPECT_DOUBLE_EQ(identity.iterationMessageSizes.verification.averageBytes, 7.0);
    // One setup per scenario instance (one per effective worker). FakeScenario
    // instance i reports generateKeys.totalMs = i + 1 and keyGeneration
    // totalBytes = 1000 + i over a single call/message, so the merged setup
    // record spans every worker's setup: raw totals/counts sum across workers
    // and the averages are recomputed from the merged totals.
    const std::size_t workers = identity.effectiveThreads;
    const std::size_t setupTotalBytes =
        1000 * workers + workers * (workers - 1) / 2;
    EXPECT_DOUBLE_EQ(identity.setupTimings.generateKeys.totalMs,
                     static_cast<double>(workers * (workers + 1) / 2));
    EXPECT_EQ(identity.setupTimings.generateKeys.callCount, workers);
    EXPECT_DOUBLE_EQ(identity.setupTimings.generateKeys.averageMs,
                     static_cast<double>(workers + 1) / 2.0);
    EXPECT_EQ(identity.setupMessageSizes.keyGeneration.totalBytes, setupTotalBytes);
    EXPECT_EQ(identity.setupMessageSizes.keyGeneration.messageCount, workers);
    EXPECT_DOUBLE_EQ(identity.setupMessageSizes.keyGeneration.averageBytes,
                     static_cast<double>(setupTotalBytes) / workers);
}

void expectDistinctScenarioPartition(const FakeScenarioSharedState& state,
                                     std::size_t iterations, std::size_t effectiveThreads)
{
    // The runner validated exactly one plan — worker 0's, before any worker
    // setup ran — and that plan is the schedule it executed below.
    EXPECT_EQ(state.validateCalls.load(), 1U);
    const BenchmarkRunPlan& plan = state.validatedPlan;
    EXPECT_EQ(plan.effectiveThreads(), effectiveThreads);
    expectPlanRanges(plan);
    EXPECT_EQ(plan.slotBegin(effectiveThreads), iterations);

    // Exactly one scenario instance per effective worker, none extra.
    EXPECT_EQ(state.nextInstanceId.load(), effectiveThreads);
    // Every requested iteration ran exactly once across all workers.
    EXPECT_EQ(state.totalIterations.load(), iterations);

    std::vector<std::size_t> actual;
    for (std::size_t i = 0; i < state.instances.size(); ++i) {
        const std::size_t run = state.instances[i].iterations.load();
        const std::size_t setups = state.instances[i].setups.load();
        const std::size_t teardowns = state.instances[i].teardowns.load();
        const std::size_t prematureSetups =
            state.instances[i].setupsBeforeValidation.load();
        EXPECT_EQ(prematureSetups, 0U) << "scenario instance " << i << " setup ran before validateRun";
        if (run > 0) {
            actual.push_back(run);
            EXPECT_EQ(setups, 1U) << "scenario instance " << i << ": setup count";
            EXPECT_EQ(teardowns, 1U) << "scenario instance " << i << ": teardown count";
        } else {
            EXPECT_EQ(setups, 0U) << "scenario instance " << i << ": idle setups";
            EXPECT_EQ(teardowns, 0U) << "scenario instance " << i << ": idle teardowns";
        }
    }

    // Each worker must have run exactly one of the plan's slots: shared
    // instances or unbalanced slots break this multiset.
    std::vector<std::size_t> expected;
    expected.reserve(effectiveThreads);
    for (std::size_t slot = 0; slot < plan.effectiveThreads(); ++slot) {
        expected.push_back(plan.slotCount(slot));
    }
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    ASSERT_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(actual[i], expected[i]) << "worker slot sizes mismatch";
    }
}

TEST(BenchmarkRunnerTest, SingleThreadRunsEveryIterationOnOneScenario)
{
    FakeScenarioSharedState state;
    auto raw = runFakeBenchmark(state, 5, 1);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const IdentityResult&>(*raw);

    EXPECT_EQ(result.requestedThreads, 1U);
    EXPECT_EQ(result.effectiveThreads, 1U);
    expectFullRunRecorded(result, 5);
    expectDistinctScenarioPartition(state, 5, 1);
}

TEST(BenchmarkRunnerTest, ParallelSplitRunsEveryIterationOnceAcrossDistinctScenarios)
{
    FakeScenarioSharedState state;
    auto raw = runFakeBenchmark(state, 10, 4);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const IdentityResult&>(*raw);

    EXPECT_EQ(result.requestedThreads, 4U);
    EXPECT_EQ(result.effectiveThreads, 4U);
    expectFullRunRecorded(result, 10);
    // Balanced static split: slots of 3, 3, 2, 2 iterations.
    expectDistinctScenarioPartition(state, 10, 4);
}

TEST(BenchmarkRunnerTest, RequestedThreadsClampToIterationCount)
{
    FakeScenarioSharedState state;
    auto raw = runFakeBenchmark(state, 3, 8);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const IdentityResult&>(*raw);

    EXPECT_EQ(result.requestedThreads, 8U);
    EXPECT_EQ(result.effectiveThreads, 3U);
    expectFullRunRecorded(result, 3);
    expectDistinctScenarioPartition(state, 3, 3);
}

TEST(BenchmarkRunnerTest, ZeroThreadsResolveToHardwareConcurrency)
{
    const std::size_t hardware = std::thread::hardware_concurrency();
    const std::size_t resolved = (hardware > 0) ? hardware : 1;
    const std::size_t iterations = 5;
    const std::size_t effective = std::min(resolved, iterations);

    FakeScenarioSharedState state;
    auto raw = runFakeBenchmark(state, iterations, 0);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const IdentityResult&>(*raw);

    EXPECT_EQ(result.requestedThreads, resolved);
    EXPECT_EQ(result.effectiveThreads, effective);
    expectFullRunRecorded(result, iterations);
    expectDistinctScenarioPartition(state, iterations, effective);
}

TEST(BenchmarkRunnerTest, UnsupportedParallelCapabilityForcesSingleThread)
{
    FakeScenarioSharedState state;
    auto raw = runFakeBenchmark(state, 6, 4, false);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const IdentityResult&>(*raw);

    // Requested parallelism is reported, but a scenario that cannot partition
    // forces one effective thread with a single scenario over all iterations.
    EXPECT_EQ(result.requestedThreads, 4U);
    EXPECT_EQ(result.effectiveThreads, 1U);
    expectFullRunRecorded(result, 6);
    expectDistinctScenarioPartition(state, 6, 1);
}

} // namespace
} // namespace CAMatrix::Audit::Benchmark
