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
 * @version 4.1.0
 * @date 2026-08-25
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
#define CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H

#include <ChordAuditMatrixBench/benchmark_types.h>

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
 *          (called by the corresponding Scenario::computeResult()).
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
        result.accuracyRate = (totalVerifySamples_ > 0)
            ? static_cast<double>(trueAccepts_ + trueRejects_)
              / static_cast<double>(totalVerifySamples_) : 0.0;
        result.trueAccepts = trueAccepts_;
        result.falseAccepts = falseAccepts_;
        result.trueRejects = trueRejects_;
        result.falseRejects = falseRejects_;
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
