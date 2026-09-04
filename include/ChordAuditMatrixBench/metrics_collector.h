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
 * GNU General Public License for more more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file metrics_collector.h
 * @brief Metrics collection and aggregation for audit benchmark runs
 * @details Collects per-iteration metrics (timings, detection results,
 *          message sizes, identity verification outcomes) and provides
 *          scenario-specific fill methods (fillPdpResult / fillIdentityResult)
 *          called by each concrete scenario's computeResult() to populate the
 *          polymorphic result hierarchy.
 * @author Dylan Liu
 * @version 4.2.0
 * @date 2026-09-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
#define CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <algorithm>
#include <cstddef>
#include <string>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class MetricsCollector
 * @brief Collects and aggregates metrics from multiple benchmark iterations
 * @details Supports both PDP audit scenarios (confidence rate via recordOutcome)
 *          and identity verification scenarios (accuracy rate via
 *          recordIdentityOutcome). The legacy computeResult() with ResultKind
 *          dispatch has been split into fillPdpResult() / fillIdentityResult()
 *          (called by the corresponding Scenario::computeResult()). In
 *          parallel runs each worker records into its own collector and the
 *          runner merges them via mergeFrom() before result filling.
 */
class MetricsCollector {
public:
    // ── PDP audit outcome recording ──

    /**
     * @brief Record the outcome of a single PDP audit iteration
     * @param detected Whether data incompleteness was detected
     * @param reason Human-readable detection reason (currently unused)
     */
    void recordOutcome(bool detected, const std::string& /*reason*/)
    {
        ++iterations_;
        if (detected) {
            ++detections_;
        }
    }

    // ── Identity verification outcome recording ──

    /**
     * @brief Record the outcome of a single identity verification sample
     * @param accepted Whether the signature was accepted by the verifier
     * @param groundTruth Whether the signature should have been accepted
     */
    void recordIdentityOutcome(bool accepted, bool groundTruth)
    {
        ++totalVerifySamples_;
        if (accepted && groundTruth) {
            ++trueAccepts_;
        } else if (accepted && !groundTruth) {
            ++falseAccepts_;
        } else if (!accepted && !groundTruth) {
            ++trueRejects_;
        } else {
            ++falseRejects_;
        }
    }

    // ── Setup metrics ──

    /**
     * @brief Record the one-time setup stage timings
     * @param timings Setup-stage timing measurements to store
     */
    void recordSetupTimings(const StageTimings& timings)
    {
        if (setupTimingsRecorded_) {
            return;
        }
        setupTimings_ = timings;
        normalize(setupTimings_);
        setupTimingsRecorded_ = true;
    }

    /**
     * @brief Record the one-time setup communication metrics
     * @param sizes Setup-stage serialized message measurements to store
     */
    void recordSetupMessageSizes(const MessageSizes& sizes)
    {
        if (setupMessageSizesRecorded_) {
            return;
        }
        setupMessageSizes_ = sizes;
        normalize(setupMessageSizes_);
        setupMessageSizesRecorded_ = true;
    }

    // ── Per-iteration metrics ──

    /**
     * @brief Add stage timings from one iteration
     * @param timings Per-iteration timing measurements
     */
    void recordTimings(const StageTimings& timings)
    {
        add(iterationTimings_.initAlgorithm, timings.initAlgorithm);
        add(iterationTimings_.generateKeys, timings.generateKeys);
        add(iterationTimings_.generateTags, timings.generateTags);
        add(iterationTimings_.generateChallenges, timings.generateChallenges);
        add(iterationTimings_.generateProofs, timings.generateProofs);
        add(iterationTimings_.verifyProofs, timings.verifyProofs);
        add(iterationTimings_.sign, timings.sign);
        add(iterationTimings_.aggregateVerify, timings.aggregateVerify);
        add(iterationTimings_.aggregate, timings.aggregate);
        add(iterationTimings_.maintain, timings.maintain);
    }

    /**
     * @brief Add communication metrics from one iteration
     * @param sizes Per-iteration serialized message measurements
     */
    void recordMessageSizes(const MessageSizes& sizes)
    {
        add(iterationMessageSizes_.challenge, sizes.challenge);
        add(iterationMessageSizes_.proof, sizes.proof);
        add(iterationMessageSizes_.keyGeneration, sizes.keyGeneration);
        add(iterationMessageSizes_.signing, sizes.signing);
        add(iterationMessageSizes_.verification, sizes.verification);
    }

    /**
     * @brief Set peak memory usage
     * @param bytes Peak memory usage in bytes
     */
    void setMemoryPeak(std::size_t bytes)
    {
        memoryPeakBytes_ = bytes;
    }

    // ── Scenario-specific result fillers ──

    /**
     * @brief Fill a PdpAuditResult with PDP-specific and common metrics
     * @param result [OUT] PDP result to populate
     * @param config PDP configuration used for the run
     */
    void fillPdpResult(PdpAuditResult& result, const PdpAuditConfig& config) const
    {
        result.totalBlocks = config.totalBlocks;
        result.corruptedBlocks = config.corruptedBlocks;
        result.sampleSize = config.sampleSize;
        result.maintenanceOps = config.maintenanceOps;
        result.detections = detections_;
        result.confidenceRate = (iterations_ > 0)
            ? static_cast<double>(detections_) / static_cast<double>(iterations_) : 0.0;
        fillCommonMetrics(result, config);
    }

    /**
     * @brief Fill an IdentityResult with identity-specific and common metrics
     * @param result [OUT] Identity result to populate
     * @param config Identity configuration used for the run
     */
    void fillIdentityResult(IdentityResult& result, const IdentityConfig& config) const
    {
        result.numUsers = config.numUsers;
        result.totalVerifySamples = totalVerifySamples_;
        result.averageVerifySamples = averagePerIteration(
            totalVerifySamples_, config.iterations);
        result.accuracyRate = (totalVerifySamples_ > 0)
            ? static_cast<double>(trueAccepts_ + trueRejects_)
              / static_cast<double>(totalVerifySamples_) : 0.0;
        result.trueAccepts = trueAccepts_;
        result.falseAccepts = falseAccepts_;
        result.trueRejects = trueRejects_;
        result.falseRejects = falseRejects_;
        result.averageTrueAccepts = averagePerIteration(trueAccepts_, config.iterations);
        result.averageFalseAccepts = averagePerIteration(falseAccepts_, config.iterations);
        result.averageTrueRejects = averagePerIteration(trueRejects_, config.iterations);
        result.averageFalseRejects = averagePerIteration(falseRejects_, config.iterations);
        fillCommonMetrics(result, config);
    }

    // ── Reset ──

    /**
     * @brief Reset all collected metrics
     */
    void reset()
    {
        iterations_ = 0;
        detections_ = 0;
        totalVerifySamples_ = 0;
        trueAccepts_ = 0;
        falseAccepts_ = 0;
        trueRejects_ = 0;
        falseRejects_ = 0;
        setupTimings_ = StageTimings{};
        iterationTimings_ = StageTimings{};
        setupMessageSizes_ = MessageSizes{};
        iterationMessageSizes_ = MessageSizes{};
        setupTimingsRecorded_ = false;
        setupMessageSizesRecorded_ = false;
        memoryPeakBytes_ = 0;
    }

    // ── Merge (parallel-run worker collectors) ──

    /**
     * @brief Merge raw metrics from a worker-local collector into this one
     * @details Sums raw totals, call counts, byte counts, and outcome counters
     *          across both collectors — per-iteration and setup-stage timings,
     *          message sizes, PDP detections, and identity TP/FP/TN/FN samples.
     *          Averages are recomputed from the merged totals here (per add),
     *          so each average is derived from the full run rather than from
     *          averaging per-worker averages; derived per-iteration rates are
     *          computed only at result filling time from the config iteration
     *          count. Setup-phase metrics merge exactly like per-iteration
     *          ones: every worker performs its own one-time setup, so the
     *          summed totals/counts span every worker's setup and the
     *          normalized averages weight each worker by its call or message
     *          count. A side that never recorded setup data contributes zero
     *          totals and cannot clear the other side's recorded flag; when
     *          only the donor recorded, its record is adopted, and the flag
     *          stays clear only when neither side recorded. The memory peak
     *          takes the higher of the two values.
     * @param other Worker-local collector to merge into this one
     */
    void mergeFrom(const MetricsCollector& other)
    {
        add(iterationTimings_.initAlgorithm, other.iterationTimings_.initAlgorithm);
        add(iterationTimings_.generateKeys, other.iterationTimings_.generateKeys);
        add(iterationTimings_.generateTags, other.iterationTimings_.generateTags);
        add(iterationTimings_.generateChallenges, other.iterationTimings_.generateChallenges);
        add(iterationTimings_.generateProofs, other.iterationTimings_.generateProofs);
        add(iterationTimings_.verifyProofs, other.iterationTimings_.verifyProofs);
        add(iterationTimings_.sign, other.iterationTimings_.sign);
        add(iterationTimings_.aggregateVerify, other.iterationTimings_.aggregateVerify);
        add(iterationTimings_.aggregate, other.iterationTimings_.aggregate);
        add(iterationTimings_.maintain, other.iterationTimings_.maintain);

        add(iterationMessageSizes_.tags, other.iterationMessageSizes_.tags);
        add(iterationMessageSizes_.challenge, other.iterationMessageSizes_.challenge);
        add(iterationMessageSizes_.proof, other.iterationMessageSizes_.proof);
        add(iterationMessageSizes_.keyGeneration, other.iterationMessageSizes_.keyGeneration);
        add(iterationMessageSizes_.signing, other.iterationMessageSizes_.signing);
        add(iterationMessageSizes_.verification, other.iterationMessageSizes_.verification);

        add(setupTimings_.initAlgorithm, other.setupTimings_.initAlgorithm);
        add(setupTimings_.generateKeys, other.setupTimings_.generateKeys);
        add(setupTimings_.generateTags, other.setupTimings_.generateTags);
        add(setupTimings_.generateChallenges, other.setupTimings_.generateChallenges);
        add(setupTimings_.generateProofs, other.setupTimings_.generateProofs);
        add(setupTimings_.verifyProofs, other.setupTimings_.verifyProofs);
        add(setupTimings_.sign, other.setupTimings_.sign);
        add(setupTimings_.aggregateVerify, other.setupTimings_.aggregateVerify);
        add(setupTimings_.aggregate, other.setupTimings_.aggregate);
        add(setupTimings_.maintain, other.setupTimings_.maintain);

        add(setupMessageSizes_.tags, other.setupMessageSizes_.tags);
        add(setupMessageSizes_.challenge, other.setupMessageSizes_.challenge);
        add(setupMessageSizes_.proof, other.setupMessageSizes_.proof);
        add(setupMessageSizes_.keyGeneration, other.setupMessageSizes_.keyGeneration);
        add(setupMessageSizes_.signing, other.setupMessageSizes_.signing);
        add(setupMessageSizes_.verification, other.setupMessageSizes_.verification);

        iterations_ += other.iterations_;
        detections_ += other.detections_;
        totalVerifySamples_ += other.totalVerifySamples_;
        trueAccepts_ += other.trueAccepts_;
        falseAccepts_ += other.falseAccepts_;
        trueRejects_ += other.trueRejects_;
        falseRejects_ += other.falseRejects_;
        memoryPeakBytes_ = std::max(memoryPeakBytes_, other.memoryPeakBytes_);
        setupTimingsRecorded_ = setupTimingsRecorded_ || other.setupTimingsRecorded_;
        setupMessageSizesRecorded_ =
            setupMessageSizesRecorded_ || other.setupMessageSizesRecorded_;
    }

private:
    // ── PDP audit counters ──
    std::size_t iterations_ = 0;
    std::size_t detections_ = 0;

    // ── Identity verification counters ──
    std::size_t totalVerifySamples_ = 0;
    std::size_t trueAccepts_ = 0;
    std::size_t falseAccepts_ = 0;
    std::size_t trueRejects_ = 0;
    std::size_t falseRejects_ = 0;

    // ── Setup metrics (one-time) ──
    StageTimings setupTimings_;
    MessageSizes setupMessageSizes_;
    bool setupTimingsRecorded_ = false;
    bool setupMessageSizesRecorded_ = false;

    // ── Per-iteration metrics ──
    StageTimings iterationTimings_;
    MessageSizes iterationMessageSizes_;

    std::size_t memoryPeakBytes_ = 0;

    static double averagePerIteration(std::size_t total, std::size_t iterations)
    {
        return (iterations > 0)
            ? static_cast<double>(total) / static_cast<double>(iterations) : 0.0;
    }
    static void normalize(TimingMetric& metric)
    {
        metric.averageMs = (metric.callCount > 0)
            ? metric.totalMs / static_cast<double>(metric.callCount) : 0.0;
    }

    static void normalize(MessageMetric& metric)
    {
        metric.averageBytes = (metric.messageCount > 0)
            ? static_cast<double>(metric.totalBytes)
              / static_cast<double>(metric.messageCount) : 0.0;
    }

    static void normalize(StageTimings& timings)
    {
        normalize(timings.initAlgorithm);
        normalize(timings.generateKeys);
        normalize(timings.generateTags);
        normalize(timings.generateChallenges);
        normalize(timings.generateProofs);
        normalize(timings.verifyProofs);
        normalize(timings.sign);
        normalize(timings.aggregateVerify);
        normalize(timings.aggregate);
        normalize(timings.maintain);
    }

    static void normalize(MessageSizes& sizes)
    {
        normalize(sizes.challenge);
        normalize(sizes.proof);
        normalize(sizes.keyGeneration);
        normalize(sizes.signing);
        normalize(sizes.verification);
    }

    static void add(TimingMetric& total, const TimingMetric& sample)
    {
        total.totalMs += sample.totalMs;
        total.callCount += sample.callCount;
        normalize(total);
    }

    static void add(MessageMetric& total, const MessageMetric& sample)
    {
        total.totalBytes += sample.totalBytes;
        total.messageCount += sample.messageCount;
        normalize(total);
    }

    void fillCommonMetrics(BenchmarkResult& result, const BenchmarkConfig& config) const
    {
        result.iterations = config.iterations;
        result.setupTimings = setupTimings_;
        result.iterationTimings = iterationTimings_;
        result.setupMessageSizes = setupMessageSizes_;
        result.iterationMessageSizes = iterationMessageSizes_;
        result.memoryPeakBytes = memoryPeakBytes_;
    }
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
