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
 * @file benchmark_report.cpp
 * @brief Polymorphic report implementations
 * @details Concrete toConsole()/toJson() for PdpDirectReport,
 *          PdpFixedRatioReport, PdpInverseConfidenceReport, IdentityReport.
 *          All fields are read from the typed result pointers extracted by
 *          the PdpReportBase / IdentityReport constructors. IdentityReport
 *          additionally reports the online tier, aggregation-stage timing,
 *          aggregate signature communication, and rejected aggregations.
 * @author Dylan Liu
 * @version 4.1.0
 * @date 2026-08-25
 */

#include <ChordAuditMatrixBench/benchmark_report.h>

#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>

namespace CAMatrix::Audit::Benchmark {

namespace {

/// Format a double in [0,1] as a fixed-point percentage string (e.g. "1.00%")
std::string pct(double v)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(2) << (v * 100.0) << '%';
    return os.str();
}

/// Build a PDP report banner
std::string pdpBanner(const std::string& algorithmType, const char* title)
{
    std::ostringstream oss;
    oss << "\n╔══════════════════════════════════════════════════════════════════╗\n";
    oss << "║  " << title << " — " << algorithmType;
    std::size_t padLen = 60 - (std::size_t)std::string(title).size() - algorithmType.size() - 3;
    for (std::size_t i = 0; i < padLen; ++i) oss << ' ';
    oss << "║\n";
    oss << "╚══════════════════════════════════════════════════════════════════╝\n\n";
    return oss.str();
}

/// Format one timing metric for console output.
std::string timingSummary(const TimingMetric& metric)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << metric.totalMs << " ms total, "
        << metric.averageMs << " ms avg ("
        << metric.callCount << " calls)";
    return oss.str();
}

/// Format one communication metric for console output.
std::string messageSummary(const MessageMetric& metric)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << metric.totalBytes << " bytes total, "
        << metric.averageBytes << " bytes avg ("
        << metric.messageCount << " messages)";
    return oss.str();
}

/// Format one timing metric as JSON.
std::string timingMetricJson(const TimingMetric& metric)
{
    std::ostringstream oss;
    oss << "{\"totalMs\":" << metric.totalMs
        << ",\"averageMs\":" << metric.averageMs
        << ",\"callCount\":" << metric.callCount << "}";
    return oss.str();
}

/// Format one communication metric as JSON.
std::string messageMetricJson(const MessageMetric& metric)
{
    std::ostringstream oss;
    oss << "{\"totalBytes\":" << metric.totalBytes
        << ",\"averageBytes\":" << metric.averageBytes
        << ",\"messageCount\":" << metric.messageCount << "}";
    return oss.str();
}


/// Common PDP performance-summary block (setup/iteration metrics + message sizes)
std::string pdpPerformanceSummary(const PdpAuditResult& r)
{
    std::ostringstream oss;
    oss << "  N=" << r.totalBlocks
        << " t=" << r.corruptedBlocks
        << " r=" << r.sampleSize << ":\n";
    oss << "    Setup (one-time):\n";
    oss << "      Init algorithm:   " << timingSummary(r.setupTimings.initAlgorithm) << "\n";
    oss << "      Key generation:   " << timingSummary(r.setupTimings.generateKeys) << "\n";
    oss << "      Tag generation:   " << timingSummary(r.setupTimings.generateTags) << "\n";
    if (r.setupMessageSizes.tags.messageCount > 0) {
        oss << "      Tag set:          " << messageSummary(r.setupMessageSizes.tags) << "\n";
    }
    if (r.setupTimings.maintain.callCount > 0) {
        oss << "      Maintenance:      " << timingSummary(r.setupTimings.maintain) << "\n";
    }
    oss << "    Iteration totals:\n";
    oss << "      Challenge gen:    " << timingSummary(r.iterationTimings.generateChallenges) << "\n";
    oss << "      Proof gen:        " << timingSummary(r.iterationTimings.generateProofs) << "\n";
    oss << "      Verification:     " << timingSummary(r.iterationTimings.verifyProofs) << "\n";
    if (r.iterationMessageSizes.challenge.messageCount > 0
        || r.iterationMessageSizes.proof.messageCount > 0) {
        oss << "    Iteration message sizes:\n";
        oss << "      Challenge:        " << messageSummary(r.iterationMessageSizes.challenge) << "\n";
        oss << "      Proof:            " << messageSummary(r.iterationMessageSizes.proof) << "\n";
    }
    return oss.str();
}

/// Common PDP JSON block for one result (timing + message + memory)
std::string pdpCommonJson(const PdpAuditResult& r, const std::string& indent)
{
    std::ostringstream oss;
    oss << indent << "  \"setupTimings\": {\n";
    oss << indent << "    \"initAlgorithm\": " << timingMetricJson(r.setupTimings.initAlgorithm) << ",\n";
    oss << indent << "    \"generateKeys\": " << timingMetricJson(r.setupTimings.generateKeys) << ",\n";
    oss << indent << "    \"generateTags\": " << timingMetricJson(r.setupTimings.generateTags) << ",\n";
    oss << indent << "    \"maintain\": " << timingMetricJson(r.setupTimings.maintain) << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"iterationTimings\": {\n";
    oss << indent << "    \"generateChallenges\": " << timingMetricJson(r.iterationTimings.generateChallenges) << ",\n";
    oss << indent << "    \"generateProofs\": " << timingMetricJson(r.iterationTimings.generateProofs) << ",\n";
    oss << indent << "    \"verifyProofs\": " << timingMetricJson(r.iterationTimings.verifyProofs) << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"setupMessageSizes\": {\n";
    oss << indent << "    \"tags\": " << messageMetricJson(r.setupMessageSizes.tags) << ",\n";
    oss << indent << "    \"challenge\": " << messageMetricJson(r.setupMessageSizes.challenge) << ",\n";
    oss << indent << "    \"proof\": " << messageMetricJson(r.setupMessageSizes.proof) << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"iterationMessageSizes\": {\n";
    oss << indent << "    \"challenge\": " << messageMetricJson(r.iterationMessageSizes.challenge) << ",\n";
    oss << indent << "    \"proof\": " << messageMetricJson(r.iterationMessageSizes.proof) << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"memoryPeakBytes\": " << r.memoryPeakBytes << "\n";
    return oss.str();
}

} // anonymous namespace

// ==================================================================
// PdpDirectReport
// ==================================================================

std::string PdpDirectReport::toConsole() const
{
    if (pdpResults_.empty()) return "(no results)\n";
    std::ostringstream oss;
    oss << pdpBanner(algorithmType_, "PDP Direct Benchmark Report");

    oss << "Parameter Descriptions:\n";
    oss << "  N (totalBlocks)    — Total number of data blocks\n";
    oss << "  t (corruptedBlocks)— Number of corrupted/stale blocks\n";
    oss << "  r (sampleSize)     — Blocks sampled per audit iteration\n";
    oss << "  Confidence Rate    — Detections / iterations (empirical)\n";
    oss << "  Theoretical Rate   — Hypergeometric probability\n\n";

    oss << std::left
        << std::setw(8)  << "N"
        << std::setw(8)  << "t"
        << std::setw(8)  << "r"
        << std::setw(12) << "Iterations"
        << std::setw(16) << "Detected"
        << std::setw(16) << "ConfRate"
        << std::setw(16) << "Theoretical"
        << "\n";
    oss << std::string(84, '-') << "\n";

    for (const auto* r : pdpResults_) {
        if (!r) continue;
        oss << std::left
            << std::setw(8)  << r->totalBlocks
            << std::setw(8)  << r->corruptedBlocks
            << std::setw(8)  << r->sampleSize
            << std::setw(12) << r->iterations
            << std::setw(16) << r->detections
            << std::setw(16) << std::fixed << std::setprecision(2) << r->confidenceRate
            << std::setw(16) << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate
            << "\n";
    }

    oss << "\n── Performance Summary ──\n";
    for (const auto* r : pdpResults_) {
        if (r) oss << pdpPerformanceSummary(*r);
    }
    return oss.str();
}

std::string PdpDirectReport::toJson() const
{
    if (pdpResults_.empty()) {
        return "{ \"computation\": \"PdpDirect\", \"algorithmType\": \"" + algorithmType_ + "\", \"results\": [] }\n";
    }
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"computation\": \"PdpDirect\",\n";
    oss << "  \"algorithmType\": \"" << algorithmType_ << "\",\n";
    oss << "  \"results\": [\n";
    for (std::size_t i = 0; i < pdpResults_.size(); ++i) {
        const auto* r = pdpResults_[i];
        if (!r) continue;
        oss << "    {\n";
        oss << "      \"totalBlocks\": " << r->totalBlocks << ",\n";
        oss << "      \"corruptedBlocks\": " << r->corruptedBlocks << ",\n";
        oss << "      \"sampleSize\": " << r->sampleSize << ",\n";
        oss << "      \"iterations\": " << r->iterations << ",\n";
        oss << "      \"detections\": " << r->detections << ",\n";
        oss << "      \"confidenceRate\": " << std::fixed << std::setprecision(2) << r->confidenceRate << ",\n";
        oss << "      \"theoreticalConfidenceRate\": " << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate << ",\n";
        oss << pdpCommonJson(*r, "    ");
        oss << "    }";
        if (i + 1 < pdpResults_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n}\n";
    return oss.str();
}

// ==================================================================
// PdpFixedRatioReport
// ==================================================================

std::string PdpFixedRatioReport::toConsole() const
{
    if (pdpResults_.empty()) return "(no results)\n";
    std::ostringstream oss;
    oss << pdpBanner(algorithmType_, "PDP FixedRatio Benchmark Report");

    oss << "Parameter Descriptions:\n";
    oss << "  N              — Total data blocks\n";
    oss << "  t/N%, r/N%     — Corrupted / sampled block ratios\n";
    oss << "  Confidence Rate— Empirical detection rate\n\n";

    oss << std::left
        << std::setw(8)  << "N"
        << std::setw(10) << "t/N%"
        << std::setw(10) << "r/N%"
        << std::setw(8)  << "t"
        << std::setw(8)  << "r"
        << std::setw(12) << "Iterations"
        << std::setw(12) << "Detected"
        << std::setw(12) << "ConfRate"
        << std::setw(12) << "Theoretical"
        << "\n";
    oss << std::string(92, '-') << "\n";

    for (const auto* r : pdpResults_) {
        if (!r || r->totalBlocks == 0) continue;
        double cRatio = static_cast<double>(r->corruptedBlocks) / r->totalBlocks;
        double sRatio = static_cast<double>(r->sampleSize) / r->totalBlocks;
        oss << std::left
            << std::setw(8)  << r->totalBlocks
            << std::setw(10) << pct(cRatio)
            << std::setw(10) << pct(sRatio)
            << std::setw(8)  << r->corruptedBlocks
            << std::setw(8)  << r->sampleSize
            << std::setw(12) << r->iterations
            << std::setw(12) << r->detections
            << std::setw(12) << std::fixed << std::setprecision(2) << r->confidenceRate
            << std::setw(12) << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate
            << "\n";
    }

    oss << "\n── Performance Summary ──\n";
    for (const auto* r : pdpResults_) {
        if (r) oss << pdpPerformanceSummary(*r);
    }
    return oss.str();
}

std::string PdpFixedRatioReport::toJson() const
{
    if (pdpResults_.empty()) {
        return "{ \"computation\": \"PdpFixedRatio\", \"algorithmType\": \"" + algorithmType_ + "\", \"results\": [] }\n";
    }
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"computation\": \"PdpFixedRatio\",\n";
    oss << "  \"algorithmType\": \"" << algorithmType_ << "\",\n";
    oss << "  \"results\": [\n";
    for (std::size_t i = 0; i < pdpResults_.size(); ++i) {
        const auto* r = pdpResults_[i];
        if (!r) continue;
        double cRatio = (r->totalBlocks > 0)
            ? static_cast<double>(r->corruptedBlocks) / r->totalBlocks : 0.0;
        double sRatio = (r->totalBlocks > 0)
            ? static_cast<double>(r->sampleSize) / r->totalBlocks : 0.0;
        oss << "    {\n";
        oss << "      \"totalBlocks\": " << r->totalBlocks << ",\n";
        oss << "      \"corruptedBlocks\": " << r->corruptedBlocks << ",\n";
        oss << "      \"sampleSize\": " << r->sampleSize << ",\n";
        oss << "      \"iterations\": " << r->iterations << ",\n";
        oss << "      \"detections\": " << r->detections << ",\n";
        oss << "      \"confidenceRate\": " << std::fixed << std::setprecision(2) << r->confidenceRate << ",\n";
        oss << "      \"theoreticalConfidenceRate\": " << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate << ",\n";
        oss << "      \"corruptionRatio\": " << std::fixed << std::setprecision(2) << cRatio << ",\n";
        oss << "      \"samplingRatio\": " << std::fixed << std::setprecision(2) << sRatio << ",\n";
        oss << pdpCommonJson(*r, "    ");
        oss << "    }";
        if (i + 1 < pdpResults_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n}\n";
    return oss.str();
}

// ==================================================================
// PdpInverseConfidenceReport
// ==================================================================

std::string PdpInverseConfidenceReport::toConsole() const
{
    if (pdpResults_.empty()) return "(no results)\n";
    std::ostringstream oss;
    oss << pdpBanner(algorithmType_, "PDP InverseConfidence Benchmark Report");

    oss << "Parameter Descriptions:\n";
    oss << "  N              — Total data blocks\n";
    oss << "  t/N%, r/N%     — Corrupted / sampled block ratios\n";
    oss << "  r              — Min samples to hit target confidence P*\n";
    oss << "  Confidence Rate— Empirical detection rate\n\n";

    oss << std::left
        << std::setw(8)  << "N"
        << std::setw(10) << "t/N%"
        << std::setw(8)  << "r"
        << std::setw(10) << "r/N%"
        << std::setw(14) << "ConfRate"
        << std::setw(14) << "Theoretical"
        << std::setw(12) << "Iterations"
        << "\n";
    oss << std::string(76, '-') << "\n";

    for (const auto* r : pdpResults_) {
        if (!r || r->totalBlocks == 0) continue;
        double cRatio = static_cast<double>(r->corruptedBlocks) / r->totalBlocks;
        double sRatio = static_cast<double>(r->sampleSize) / r->totalBlocks;
        oss << std::left
            << std::setw(8)  << r->totalBlocks
            << std::setw(10) << pct(cRatio)
            << std::setw(8)  << r->sampleSize
            << std::setw(10) << pct(sRatio)
            << std::setw(14) << std::fixed << std::setprecision(2) << r->confidenceRate
            << std::setw(14) << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate
            << std::setw(12) << r->iterations
            << "\n";
    }

    oss << "\n── Performance Summary ──\n";
    for (const auto* r : pdpResults_) {
        if (r) oss << pdpPerformanceSummary(*r);
    }
    return oss.str();
}

std::string PdpInverseConfidenceReport::toJson() const
{
    if (pdpResults_.empty()) {
        return "{ \"computation\": \"PdpInverseConfidence\", \"algorithmType\": \"" + algorithmType_ + "\", \"results\": [] }\n";
    }
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"computation\": \"PdpInverseConfidence\",\n";
    oss << "  \"algorithmType\": \"" << algorithmType_ << "\",\n";
    oss << "  \"results\": [\n";
    for (std::size_t i = 0; i < pdpResults_.size(); ++i) {
        const auto* r = pdpResults_[i];
        if (!r) continue;
        double cRatio = (r->totalBlocks > 0)
            ? static_cast<double>(r->corruptedBlocks) / r->totalBlocks : 0.0;
        double sRatio = (r->totalBlocks > 0)
            ? static_cast<double>(r->sampleSize) / r->totalBlocks : 0.0;
        oss << "    {\n";
        oss << "      \"totalBlocks\": " << r->totalBlocks << ",\n";
        oss << "      \"corruptedBlocks\": " << r->corruptedBlocks << ",\n";
        oss << "      \"sampleSize\": " << r->sampleSize << ",\n";
        oss << "      \"iterations\": " << r->iterations << ",\n";
        oss << "      \"detections\": " << r->detections << ",\n";
        oss << "      \"confidenceRate\": " << std::fixed << std::setprecision(2) << r->confidenceRate << ",\n";
        oss << "      \"theoreticalConfidenceRate\": " << std::fixed << std::setprecision(2) << r->theoreticalConfidenceRate << ",\n";
        oss << "      \"corruptionRatio\": " << std::fixed << std::setprecision(2) << cRatio << ",\n";
        oss << "      \"samplingRatio\": " << std::fixed << std::setprecision(2) << sRatio << ",\n";
        oss << pdpCommonJson(*r, "    ");
        oss << "    }";
        if (i + 1 < pdpResults_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n}\n";
    return oss.str();
}

// ==================================================================
// IdentityReport
// ==================================================================

std::string IdentityReport::toConsole() const
{
    if (identityResults_.empty()) return "(no results)\n";
    std::ostringstream oss;
    const char* kind = (identityResults_.front())
        ? identityResults_.front()->algorithmKind.c_str() : "Unknown";
    oss << "\n╔══════════════════════════════════════════════════════════════════╗\n";
    oss << "║     Identity Verification Benchmark Report — " << algorithmType_;
    std::size_t padLen = 19 - algorithmType_.size();
    for (std::size_t i = 0; i < padLen; ++i) oss << ' ';
    oss << "║\n";
    oss << "╚══════════════════════════════════════════════════════════════════╝\n\n";

    oss << "  Algorithm kind: " << kind << "\n\n";

    oss << "Parameter Descriptions:\n";
    oss << "  Users             — Enrolled users\n";
    oss << "  Samples/Iter      — Verification samples per iteration\n";
    oss << "  Accuracy Rate     — (TP + TN) / total\n";
    oss << "  TP/FP/TN/FN       — True/false accepts/rejects\n\n";

    oss << std::left
        << std::setw(8)  << "Users"
        << std::setw(12) << "Samples"
        << std::setw(12) << "Iterations"
        << std::setw(14) << "Accuracy"
        << std::setw(10) << "TP"
        << std::setw(10) << "FP"
        << std::setw(10) << "TN"
        << std::setw(10) << "FN"
        << "\n";
    oss << std::string(100, '-') << "\n";

    for (const auto* r : identityResults_) {
        if (!r) continue;
        oss << std::left
            << std::setw(8)  << r->numUsers
            << std::setw(12) << r->totalVerifySamples
            << std::setw(12) << r->iterations
            << std::fixed << std::setprecision(2)
            << std::setw(14) << r->accuracyRate
            << std::setw(10) << r->trueAccepts
            << std::setw(10) << r->falseAccepts
            << std::setw(10) << r->trueRejects
            << std::setw(10) << r->falseRejects
            << "\n";
    }

    oss << "\n── Performance Summary ──\n";
    for (const auto* r : identityResults_) {
        if (!r) continue;
        oss << "  Users=" << r->numUsers
            << " Samples=" << r->totalVerifySamples << ":\n";
        oss << "    Setup (one-time):\n";
        oss << "      Init algorithm:   " << timingSummary(r->setupTimings.initAlgorithm) << "\n";
        oss << "      Key generation:   " << timingSummary(r->setupTimings.generateKeys) << "\n";
        oss << "    Iteration totals:\n";
        oss << "      Sign:             " << timingSummary(r->iterationTimings.sign) << "\n";
        if (r->iterationTimings.aggregate.callCount > 0) {
            oss << "      Aggregate:        " << timingSummary(r->iterationTimings.aggregate) << "\n";
        }
        oss << "      Aggregate verify: " << timingSummary(r->iterationTimings.aggregateVerify) << "\n";
        if (r->setupMessageSizes.keyGeneration.messageCount > 0) {
            oss << "    Setup message sizes:\n";
            oss << "      Key generation:   " << messageSummary(r->setupMessageSizes.keyGeneration) << "\n";
        }
        if (r->iterationMessageSizes.signing.messageCount > 0
            || r->iterationMessageSizes.verification.messageCount > 0) {
            oss << "    Iteration message sizes:\n";
            oss << "      Signing:          " << messageSummary(r->iterationMessageSizes.signing) << "\n";
            oss << "      Verification:     " << messageSummary(r->iterationMessageSizes.verification) << "\n";
        }
        oss << "    Confusion Matrix:\n";
        oss << "                    Predicted Accept  Predicted Reject\n";
        oss << "      Actual Accept   TP=" << r->trueAccepts
            << "          FN=" << r->falseRejects << "\n";
        oss << "      Actual Reject   FP=" << r->falseAccepts
            << "          TN=" << r->trueRejects << "\n";
    }
    return oss.str();
}

std::string IdentityReport::toJson() const
{
    if (identityResults_.empty()) {
        return "{ \"computation\": \"IdentityVerify\", \"algorithmType\": \"" + algorithmType_ + "\", \"results\": [] }\n";
    }
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"computation\": \"IdentityVerify\",\n";
    oss << "  \"algorithmType\": \"" << algorithmType_ << "\",\n";
    oss << "  \"results\": [\n";
    for (std::size_t i = 0; i < identityResults_.size(); ++i) {
        const auto* r = identityResults_[i];
        if (!r) continue;
        oss << "    {\n";
        oss << "      \"numUsers\": " << r->numUsers << ",\n";
        oss << "      \"totalVerifySamples\": " << r->totalVerifySamples << ",\n";
        oss << "      \"iterations\": " << r->iterations << ",\n";
        oss << "      \"algorithmKind\": \"" << r->algorithmKind << "\",\n";
        oss << "      \"accuracyRate\": " << std::fixed << std::setprecision(2) << r->accuracyRate << ",\n";
        oss << "      \"trueAccepts\": " << r->trueAccepts << ",\n";
        oss << "      \"falseAccepts\": " << r->falseAccepts << ",\n";
        oss << "      \"trueRejects\": " << r->trueRejects << ",\n";
        oss << "      \"falseRejects\": " << r->falseRejects << ",\n";
        oss << "      \"setupTimings\": {\n";
        oss << "        \"initAlgorithm\": " << timingMetricJson(r->setupTimings.initAlgorithm) << ",\n";
        oss << "        \"generateKeys\": " << timingMetricJson(r->setupTimings.generateKeys) << "\n";
        oss << "      },\n";
        oss << "      \"iterationTimings\": {\n";
        oss << "        \"sign\": " << timingMetricJson(r->iterationTimings.sign) << ",\n";
        oss << "        \"aggregate\": " << timingMetricJson(r->iterationTimings.aggregate) << ",\n";
        oss << "        \"aggregateVerify\": " << timingMetricJson(r->iterationTimings.aggregateVerify) << "\n";
        oss << "      },\n";
        oss << "      \"setupMessageSizes\": {\n";
        oss << "        \"keyGeneration\": " << messageMetricJson(r->setupMessageSizes.keyGeneration) << "\n";
        oss << "      },\n";
        oss << "      \"iterationMessageSizes\": {\n";
        oss << "        \"signing\": " << messageMetricJson(r->iterationMessageSizes.signing) << ",\n";
        oss << "        \"verification\": " << messageMetricJson(r->iterationMessageSizes.verification) << "\n";
        oss << "      },\n";
        oss << "      \"memoryPeakBytes\": " << r->memoryPeakBytes << "\n";
        oss << "    }";
        if (i + 1 < identityResults_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n}\n";
    return oss.str();
}

} // namespace CAMatrix::Audit::Benchmark
