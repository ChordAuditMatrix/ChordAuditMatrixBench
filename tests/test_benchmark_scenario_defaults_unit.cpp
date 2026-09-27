/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file test_benchmark_scenario_defaults_unit.cpp
 * @brief Tests for the BenchmarkScenario defaults and the single outcome channel.
 * @details Owned by the Bench repository. A minimal scenario implements only
 *          the required lifecycle and exercises what the base class now
 *          provides: no-op prepare()/validateRun() and empty message-size
 *          getters, plus the rule that the runner records exactly one outcome
 *          per iteration through recordIteration() while runIteration() returns
 *          nothing.
 */

#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>

namespace CAMatrix::Audit::Benchmark {
namespace {

/// Minimal scenario: it implements only the lifecycle members that every
/// scenario must provide. prepare(), validateRun(), getSetupMessageSizes() and
/// getLastMessageSizes() are inherited defaults — this class would not compile
/// if the base still declared them pure virtual.
class MinimalScenario final : public BenchmarkScenario {
public:
    explicit MinimalScenario(std::atomic<std::size_t>& iterationsRun)
        : iterationsRun_(iterationsRun)
    {}

    std::string algorithmType() const override { return "Minimal"; }

    void setup(const BenchmarkConfig& /*config*/) override {}

    void runIteration() override { iterationsRun_.fetch_add(1); }

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
    std::atomic<std::size_t>& iterationsRun_; /**< Shared counter of executed iterations */
};

TEST(BenchmarkScenarioDefaultsTest, PrepareAndValidateRunAndMessageGettersDefaultToInert)
{
    std::atomic<std::size_t> iterationsRun{0};
    MinimalScenario scenario(iterationsRun);
    PdpAuditConfig config;

    EXPECT_NO_THROW(scenario.prepare(config));
    EXPECT_NO_THROW(scenario.validateRun(config, BenchmarkRunPlan::balanced(6, 3)));

    const MessageSizes setupSizes = scenario.getSetupMessageSizes();
    EXPECT_EQ(setupSizes.tags.messageCount, 0U);
    EXPECT_EQ(setupSizes.keyGeneration.messageCount, 0U);
    EXPECT_EQ(setupSizes.signing.messageCount, 0U);
    const MessageSizes iterationSizes = scenario.getLastMessageSizes();
    EXPECT_EQ(iterationSizes.challenge.messageCount, 0U);
    EXPECT_EQ(iterationSizes.proof.messageCount, 0U);
    EXPECT_EQ(iterationSizes.verification.messageCount, 0U);
}

TEST(BenchmarkScenarioDefaultsTest, RunnerRecordsOneOutcomePerIterationWithInheritedDefaults)
{
    std::atomic<std::size_t> iterationsRun{0};
    BenchmarkRunner runner(BenchmarkScenarioFactory([&iterationsRun] {
        return std::make_unique<MinimalScenario>(iterationsRun);
    }));
    PdpAuditConfig config;
    config.iterations = 5;
    config.threads = 2;

    auto raw = runner.runSingle(config);
    ASSERT_NE(raw, nullptr);
    const auto& result = static_cast<const PdpAuditResult&>(*raw);

    // The default prepare()/validateRun() did not interfere, every iteration
    // ran once, and recordIteration() was the only outcome channel: it
    // reported one detection per iteration.
    EXPECT_EQ(iterationsRun.load(), 5U);
    EXPECT_EQ(result.effectiveThreads, 2U);
    EXPECT_EQ(result.detections, 5U);
    EXPECT_DOUBLE_EQ(result.confidenceRate, 1.0);
    EXPECT_FALSE(raw->algorithmType.empty());
}

} // namespace
} // namespace CAMatrix::Audit::Benchmark
