/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file test_benchmark_timing_unit.cpp
 * @brief Tests for the shared stage-timing helper (benchmark_timing.h).
 * @details Owned by the Bench repository. Covers the four behaviours every
 *          scenario relies on: void and value-returning callables, an optional
 *          metric, accumulated averages, and a throwing call that is still
 *          counted while the original exception propagates.
 */

#include <ChordAuditMatrixBench/benchmark_timing.h>

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

namespace CAMatrix::Audit::Benchmark {
namespace {

TEST(BenchmarkTimingTest, VoidCallableIsCountedAndAveraged)
{
    TimingMetric metric;

    measureTiming(metric, [] {});
    measureTiming(metric, [] {});
    measureTiming(metric, [] {});

    EXPECT_EQ(metric.callCount, 3U);
    EXPECT_GE(metric.totalMs, 0.0);
    EXPECT_DOUBLE_EQ(metric.averageMs, metric.totalMs / 3.0);
}

TEST(BenchmarkTimingTest, ValueReturningCallableForwardsItsResult)
{
    TimingMetric metric;

    const int value = measureTiming(metric, [] { return 42; });

    EXPECT_EQ(value, 42);
    EXPECT_EQ(metric.callCount, 1U);
    EXPECT_DOUBLE_EQ(metric.averageMs, metric.totalMs);
}

TEST(BenchmarkTimingTest, ThrowingCallableIsCountedAndRethrowsTheOriginalError)
{
    TimingMetric metric;

    EXPECT_THROW(
        measureTiming(metric, []() -> int {
            throw std::invalid_argument("stage failed");
        }),
        std::invalid_argument);
    EXPECT_EQ(metric.callCount, 1U);
    EXPECT_DOUBLE_EQ(metric.averageMs, metric.totalMs);

    // The exception object itself is unchanged, message included.
    try {
        measureTiming(metric, [] { throw std::runtime_error("boom"); });
        FAIL() << "the exception must propagate";
    } catch (const std::runtime_error& error) {
        EXPECT_EQ(std::string(error.what()), "boom");
    }
    EXPECT_EQ(metric.callCount, 2U);
}

TEST(BenchmarkTimingTest, VoidCallableCountsAttemptAndRethrows)
{
    TimingMetric metric;

    EXPECT_THROW(measureTiming(metric, [] { throw std::runtime_error("maintenance failed"); }),
                 std::runtime_error);
    EXPECT_EQ(metric.callCount, 1U);

    // A successful call after a failed one keeps accumulating.
    measureTiming(metric, [] {});
    EXPECT_EQ(metric.callCount, 2U);
    EXPECT_DOUBLE_EQ(metric.averageMs, metric.totalMs / 2.0);
}

TEST(BenchmarkTimingTest, NullMetricRunsTheCallUnmeasured)
{
    int calls = 0;

    EXPECT_EQ(measureTiming(nullptr, [&] { ++calls; return 7; }), 7);
    EXPECT_NO_THROW(measureTiming(static_cast<TimingMetric*>(nullptr), [&] { ++calls; }));

    EXPECT_EQ(calls, 2);
}

TEST(BenchmarkTimingTest, NullMetricStillPropagatesExceptions)
{
    EXPECT_THROW(
        measureTiming(static_cast<TimingMetric*>(nullptr),
                      [] { throw std::logic_error("unmeasured failure"); }),
        std::logic_error);
}

TEST(BenchmarkTimingTest, AddTimingAccumulatesRawTotalsAndRecomputesAverage)
{
    TimingMetric metric;

    addTiming(metric, 10.0);
    addTiming(metric, 20.0);
    addTiming(metric, 30.0, 3);

    EXPECT_EQ(metric.callCount, 5U);
    EXPECT_DOUBLE_EQ(metric.totalMs, 60.0);
    EXPECT_DOUBLE_EQ(metric.averageMs, 12.0);
}

} // namespace
} // namespace CAMatrix::Audit::Benchmark
