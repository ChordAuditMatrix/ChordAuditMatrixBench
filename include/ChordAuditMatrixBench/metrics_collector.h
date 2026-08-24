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
        ++iterations_;  // every recordOutcome() corresponds to one PDP iteration
        if (detected) {
            ++detections_;
        }
    }

    // ── Identity verification outcome recording ──

    /**
     * @brief Record the outcome of a single identity verification sample
     * @param accepted Whether the signature was accepted by the verifier
     * @param groundTruth Whether the signature should have been accepted
     * @details Increments the appropriate TP/FP/TN/FN counter.
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
     * @param timings Setup-stage timing measurements to store
     */
    void recordSetupTimings(const StageTimings& timings)
    {
        setupTimings_ = timings;
    }

    // ── Per-iteration timings ──

    /**
     * @brief Record stage timings for a single iteration
     * @param timings Per-stage timing measurements from one iteration
     */
    void recordTimings(const StageTimings& timings)
    {
        genChallengesMs_.push_back(timings.genChallengesMs);
        genProofsMs_.push_back(timings.genProofsMs);
        verifyProofsMs_.push_back(timings.verifyProofsMs);
        signMs_.push_back(timings.signMs);
        verifyMs_.push_back(timings.verifyMs);
        aggregateVerifyMs_.push_back(timings.aggregateVerifyMs);
        aggregateMs_.push_back(timings.aggregateMs);
        maintainMs_.push_back(timings.maintainMs);
    }

    // ── Message sizes ──

    /**
     * @brief Record message sizes from an iteration (first non-zero sample wins)
     * @param sizes Serialized message sizes from one iteration
     */
    void recordMessageSizes(const MessageSizes& sizes)
    {
        if (messageSizes_.challengeBytes == 0 && messageSizes_.signatureBytes == 0) {
            messageSizes_ = sizes;
        }
    }

    /**
     * @brief Set peak memory usage
     * @param bytes Peak memory usage in bytes
     */
    void setMemoryPeak(std::size_t bytes)
    {
        memoryPeakBytes_ = bytes;
    }

    // ── Scenario-specific result fillers (called by Scenario::computeResult) ──

    /**
     * @brief Fill a PdpAuditResult with PDP-specific + common metrics
     * @details Called by PdpAuditScenario::computeResult(). Populates
     *          totalBlocks/corruptedBlocks/sampleSize/maintenanceOps from config,
     *          detections/confidenceRate from counters, then common metrics.
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
     * @brief Fill an IdentityResult with identity-specific + common metrics
     * @details Called by IdentityVerifyScenario::computeResult().
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
        genChallengesMs_.clear();
        genProofsMs_.clear();
        verifyProofsMs_.clear();
        signMs_.clear();
        verifyMs_.clear();
        aggregateVerifyMs_.clear();
        aggregateMs_.clear();
        maintainMs_.clear();
        messageSizes_ = MessageSizes{};
        memoryPeakBytes_ = 0;
    }

private:
    // ── PDP audit counters ──
    std::size_t iterations_ = 0; /**< Total PDP audit iterations (= detections + non-detections) */
    std::size_t detections_ = 0; /**< PDP iterations that detected corruption */

    // ── Identity verification counters ──
    std::size_t totalVerifySamples_ = 0; /**< Total identity samples verified */
    std::size_t trueAccepts_ = 0; /**< True accepts (TP) */
    std::size_t falseAccepts_ = 0; /**< False accepts (FP) */
    std::size_t trueRejects_ = 0; /**< True rejects (TN) */
    std::size_t falseRejects_ = 0; /**< False rejects (FN) */

    // ── Setup timings (one-time) ──
    StageTimings setupTimings_; /**< One-time setup-stage timings */

    // ── Per-iteration timing vectors ──
    std::vector<double> genChallengesMs_; /**< Per-iteration challenge-generation times */
    std::vector<double> genProofsMs_; /**< Per-iteration proof-generation times */
    std::vector<double> verifyProofsMs_; /**< Per-iteration proof-verification times */
    std::vector<double> signMs_; /**< Per-iteration individual signing times */
    std::vector<double> verifyMs_; /**< Per-iteration individual verification times */
    std::vector<double> aggregateVerifyMs_; /**< Per-iteration aggregate-verification times */
    std::vector<double> aggregateMs_; /**< Per-iteration aggregation times (online aggregateSessionSignatures) */
    std::vector<double> maintainMs_; /**< Per-iteration dynamic-PDP maintenance times */

    // ── Message sizes ──
    MessageSizes messageSizes_; /**< First recorded message sizes */
    std::size_t memoryPeakBytes_ = 0; /**< Peak memory usage in bytes */

    // ── Helpers ──

    static double avg(const std::vector<double>& values)
    {
        if (values.empty()) return 0.0;
        return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    }

    static double minVal(const std::vector<double>& values)
    {
        if (values.empty()) return 0.0;
        return *std::min_element(values.begin(), values.end());
    }

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
        t.aggregateMs = avg(aggregateMs_);
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
        t.aggregateMs = minVal(aggregateMs_);
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
        t.aggregateMs = maxVal(aggregateMs_);
        t.maintainMs = maxVal(maintainMs_);
        return t;
    }

    /// Fill common metrics shared by all result types
    void fillCommonMetrics(BenchmarkResult& result, const BenchmarkConfig& config) const
    {
        result.iterations = config.iterations;
        result.setupTimings = setupTimings_;
        result.avgTimings = computeAvgTimings();
        result.minTimings = computeMinTimings();
        result.maxTimings = computeMaxTimings();
        result.messageSizes = messageSizes_;
        result.memoryPeakBytes = memoryPeakBytes_;
    }
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_METRICS_COLLECTOR_H
