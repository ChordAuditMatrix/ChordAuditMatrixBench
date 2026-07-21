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
 *          aggregated statistics. Supports both PDP audit and identity
 *          verification benchmark scenarios via ResultKind dispatch.
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-08
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
#define CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <algorithm>
#include <cstddef>
#include <numeric>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class MetricsCollector
 * @brief Collects and aggregates metrics from multiple benchmark iterations
 * @details Supports both PDP audit scenarios (confidence rate via recordOutcome)
 *          and identity verification scenarios (accuracy rate via
 *          recordIdentityOutcome). The computeResult() method requires a
 *          ResultKind and algorithmType to correctly populate BenchmarkResult.
 */
class MetricsCollector {
public:
    // ── PDP audit outcome recording ──

    /**
     * @brief Record the outcome of a single PDP audit iteration
     * @param detected Whether data incompleteness was detected
     */
    void recordOutcome(bool detected, const std::string& /*reason*/)
    {
        ++totalAudits_;
        if (detected) {
            ++detections_;
        }
    }

    // ── Identity verification outcome recording ──

    /**
     * @brief Record the outcome of a single identity verification sample
     * @param accepted Whether the signature was accepted by the verifier
     * @param groundTruth Whether the signature should have been accepted
     * @details Increments the appropriate TP/FP/TN/FN counter:
     *          - TP: accepted && shouldAccept (true accept)
     *          - FP: accepted && !shouldAccept (false accept)
     *          - TN: !accepted && !shouldAccept (true reject)
     *          - FN: !accepted && shouldAccept (false reject)
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

    // ── Setup timings ──

    /**
     * @brief Record the one-time setup stage timings
     * @param timings Setup stage timing measurements (initAlgo + genKeys + genTags)
     */
    void recordSetupTimings(const StageTimings& timings)
    {
        setupTimings_ = timings;
    }

    // ── Per-iteration timings ──

    /**
     * @brief Record stage timings for a single iteration (PDP audit)
     * @param timings Stage timing measurements
     */
    void recordTimings(const StageTimings& timings)
    {
        genChallengesMs_.push_back(timings.genChallengesMs);
        genProofsMs_.push_back(timings.genProofsMs);
        verifyProofsMs_.push_back(timings.verifyProofsMs);
        signMs_.push_back(timings.signMs);
        verifyMs_.push_back(timings.verifyMs);
        aggregateVerifyMs_.push_back(timings.aggregateVerifyMs);
        maintainMs_.push_back(timings.maintainMs);
    }

    // ── Message sizes ──

    /**
     * @brief Record message sizes from an iteration
     * @param sizes Message size measurements
     */
    void recordMessageSizes(const MessageSizes& sizes)
    {
        if (messageSizes_.challengeBytes == 0 && messageSizes_.signatureBytes == 0) {
            messageSizes_ = sizes;
        }
    }

    // ── Memory ──

    /**
     * @brief Set peak memory usage
     * @param bytes Peak memory usage in bytes
     */
    void setMemoryPeak(std::size_t bytes)
    {
        memoryPeakBytes_ = bytes;
    }

    // ── Result computation ──

    /**
     * @brief Compute the aggregated benchmark result
     * @param config The benchmark configuration used
     * @param resultKind Type of benchmark result (PdpAudit or IdentityVerification)
     * @param algorithmType Algorithm type identifier (e.g., "SM9Static", "SM9Noncert")
     * @return Aggregated BenchmarkResult
     */
    BenchmarkResult computeResult(const BenchmarkConfig& config,
                                  ResultKind resultKind,
                                  const std::string& algorithmType) const
    {
        BenchmarkResult result;
        result.resultKind = resultKind;
        result.algorithmType = algorithmType;
        result.iterations = config.iterations;
        result.setupTimings = setupTimings_;
        result.avgTimings = computeAvgTimings();
        result.minTimings = computeMinTimings();
        result.maxTimings = computeMaxTimings();
        result.messageSizes = messageSizes_;
        result.memoryPeakBytes = memoryPeakBytes_;

        if (resultKind == ResultKind::PdpAudit) {
            result.totalBlocks = config.totalBlocks;
            result.corruptedBlocks = config.corruptedBlocks;
            result.sampleSize = config.sampleSize;
            result.totalAudits = totalAudits_;
            result.detections = detections_;
            result.confidenceRate = (totalAudits_ > 0)
                ? static_cast<double>(detections_) / static_cast<double>(totalAudits_)
                : 0.0;
            // Dynamic PDP fields
            result.maintenanceOps = config.maintenanceOps;
        } else {
            // IdentityVerification
            result.numUsers = config.numUsers;
            result.totalVerifySamples = totalVerifySamples_;
            result.correctVerifications = trueAccepts_ + trueRejects_;
            result.accuracyRate = (totalVerifySamples_ > 0)
                ? static_cast<double>(trueAccepts_ + trueRejects_)
                  / static_cast<double>(totalVerifySamples_)
                : 0.0;
            result.trueAccepts = trueAccepts_;
            result.falseAccepts = falseAccepts_;
            result.trueRejects = trueRejects_;
            result.falseRejects = falseRejects_;
        }

        return result;
    }

    // ── Reset ──

    /**
     * @brief Reset all collected metrics
     */
    void reset()
    {
        totalAudits_ = 0;
        detections_ = 0;
        totalVerifySamples_ = 0;
        trueAccepts_ = 0;
        falseAccepts_ = 0;
        trueRejects_ = 0;
        falseRejects_ = 0;
        setupTimings_ = StageTimings{};
        genChallengesMs_.clear();
        genProofsMs_.clear();
        verifyProofsMs_.clear();
        signMs_.clear();
        verifyMs_.clear();
        aggregateVerifyMs_.clear();
        maintainMs_.clear();
        messageSizes_ = MessageSizes{};
        memoryPeakBytes_ = 0;
    }

private:
    // ── PDP audit counters ──
    std::size_t totalAudits_ = 0;
    std::size_t detections_ = 0;

    // ── Identity verification counters ──
    std::size_t totalVerifySamples_ = 0;
    std::size_t trueAccepts_ = 0;
    std::size_t falseAccepts_ = 0;
    std::size_t trueRejects_ = 0;
    std::size_t falseRejects_ = 0;

    // ── Setup timings (one-time) ──
    StageTimings setupTimings_;

    // ── Per-iteration timing vectors ──
    std::vector<double> genChallengesMs_;
    std::vector<double> genProofsMs_;
    std::vector<double> verifyProofsMs_;
    std::vector<double> signMs_;
    std::vector<double> verifyMs_;
    std::vector<double> aggregateVerifyMs_;
    std::vector<double> maintainMs_;  ///< Dynamic PDP maintenance timing

    // ── Message sizes ──
    MessageSizes messageSizes_;
    std::size_t memoryPeakBytes_ = 0;

    // ── Helpers ──

    /**
     * @brief Compute average of a vector of doubles
     * @param values Vector of timing values
     * @return Average value, or 0 if empty
     */
    static double avg(const std::vector<double>& values)
    {
        if (values.empty()) return 0.0;
        return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    }

    /**
     * @brief Compute minimum of a vector of doubles
     * @param values Vector of timing values
     * @return Minimum value, or 0 if empty
     */
    static double minVal(const std::vector<double>& values)
    {
        if (values.empty()) return 0.0;
        return *std::min_element(values.begin(), values.end());
    }

    /**
     * @brief Compute maximum of a vector of doubles
     * @param values Vector of timing values
     * @return Maximum value, or 0 if empty
     */
    static double maxVal(const std::vector<double>& values)
    {
        if (values.empty()) return 0.0;
        return *std::max_element(values.begin(), values.end());
    }

    StageTimings computeAvgTimings() const
    {
        StageTimings t;
        t.genChallengesMs = avg(genChallengesMs_);
        t.genProofsMs = avg(genProofsMs_);
        t.verifyProofsMs = avg(verifyProofsMs_);
        t.signMs = avg(signMs_);
        t.verifyMs = avg(verifyMs_);
        t.aggregateVerifyMs = avg(aggregateVerifyMs_);
        t.maintainMs = avg(maintainMs_);
        return t;
    }

    StageTimings computeMinTimings() const
    {
        StageTimings t;
        t.genChallengesMs = minVal(genChallengesMs_);
        t.genProofsMs = minVal(genProofsMs_);
        t.verifyProofsMs = minVal(verifyProofsMs_);
        t.signMs = minVal(signMs_);
        t.verifyMs = minVal(verifyMs_);
        t.aggregateVerifyMs = minVal(aggregateVerifyMs_);
        t.maintainMs = minVal(maintainMs_);
        return t;
    }

    StageTimings computeMaxTimings() const
    {
        StageTimings t;
        t.genChallengesMs = maxVal(genChallengesMs_);
        t.genProofsMs = maxVal(genProofsMs_);
        t.verifyProofsMs = maxVal(verifyProofsMs_);
        t.signMs = maxVal(signMs_);
        t.verifyMs = maxVal(verifyMs_);
        t.aggregateVerifyMs = maxVal(aggregateVerifyMs_);
        t.maintainMs = maxVal(maintainMs_);
        return t;
    }
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
