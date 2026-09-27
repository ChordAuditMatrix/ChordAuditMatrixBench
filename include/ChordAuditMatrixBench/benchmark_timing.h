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
 * @file benchmark_timing.h
 * @brief Shared stage-timing helper for benchmark scenarios
 * @details The single timing implementation used by the PDP audit, identity
 *          verification and dynamic maintenance scenarios. It times one call
 *          of a void or value-returning callable into a TimingMetric, supports
 *          an optional metric (pass nullptr to run the call unmeasured), and
 *          treats a throwing call as an attempted call: the elapsed time is
 *          still accumulated and the original exception is rethrown
 *          unchanged. Stage business logic and message-size recording stay in
 *          each scenario.
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_TIMING_H
#define CAMATRIX_AUDIT_BENCHMARK_TIMING_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <chrono>
#include <cstddef>
#include <type_traits>
#include <utility>

namespace CAMatrix::Audit::Benchmark {

/**
 * @brief Add one measured call to a timing metric
 * @details Sums the elapsed time, counts the call and recomputes the average
 *          from the accumulated totals.
 * @param metric Metric to accumulate into
 * @param totalMs Elapsed time of the call in milliseconds
 * @param callCount Number of calls this sample represents (default 1)
 */
inline void addTiming(TimingMetric& metric, double totalMs,
                      std::size_t callCount = 1)
{
    metric.totalMs += totalMs;
    metric.callCount += callCount;
    metric.averageMs = (metric.callCount > 0)
        ? metric.totalMs / static_cast<double>(metric.callCount) : 0.0;
}

/**
 * @brief Milliseconds elapsed since @p start
 * @param start Steady-clock timestamp to measure from
 * @return Elapsed milliseconds
 */
inline double elapsedMs(const std::chrono::steady_clock::time_point& start)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
}

/**
 * @brief Time one attempted call of @p action into @p metric
 * @details Overload set:
 *          - `measureTiming(metric, action)` requires a metric;
 *          - `measureTiming(pointer, action)` takes an optional metric
 *            (nullptr runs the call unmeasured).
 *          `action` may be void or value-returning; a value-returning call
 *          forwards its result to the caller. A throwing call still counts as
 *          one attempted call (elapsed time accumulated, callCount
 *          incremented) and the original exception propagates.
 * @tparam F Callable type
 * @param metric Metric to accumulate into, or nullptr to skip measurement
 * @param action Callable to invoke exactly once
 * @return Whatever @p action returns (nothing when it is void)
 */
template <typename F>
auto measureTiming(TimingMetric* metric, F&& action) -> std::invoke_result_t<F>
{
    using Result = std::invoke_result_t<F>;
    if (metric == nullptr) {
        if constexpr (std::is_void_v<Result>) {
            std::forward<F>(action)();
            return;
        } else {
            return std::forward<F>(action)();
        }
    }

    const auto start = std::chrono::steady_clock::now();
    try {
        if constexpr (std::is_void_v<Result>) {
            std::forward<F>(action)();
            addTiming(*metric, elapsedMs(start));
        } else {
            Result result = std::forward<F>(action)();
            addTiming(*metric, elapsedMs(start));
            return result;
        }
    } catch (...) {
        addTiming(*metric, elapsedMs(start));
        throw;
    }
}

/**
 * @brief Time one attempted call of @p action into a required metric
 * @tparam F Callable type
 * @param metric Metric to accumulate into
 * @param action Callable to invoke exactly once
 * @return Whatever @p action returns (nothing when it is void)
 */
template <typename F>
auto measureTiming(TimingMetric& metric, F&& action) -> std::invoke_result_t<F>
{
    return measureTiming(&metric, std::forward<F>(action));
}

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_TIMING_H
