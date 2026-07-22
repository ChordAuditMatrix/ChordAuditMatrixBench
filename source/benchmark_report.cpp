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
 *          the PdpReportBase / IdentityReport constructors.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
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

/// Common PDP performance-summary block (setup/iteration timings + message sizes)
std::string pdpPerformanceSummary(const PdpAuditResult& r)
{
    std::ostringstream oss;
    oss << "  N=" << r.totalBlocks
        << " t=" << r.corruptedBlocks
        << " r=" << r.sampleSize << ":\n";
    oss << "    Setup (one-time):\n";
    oss << "      Init algorithm:   " << std::fixed << std::setprecision(2)
        << r.setupTimings.initAlgoMs << " ms\n";
    oss << "      Key generation:   " << r.setupTimings.genKeysMs << " ms\n";
    oss << "      Tag generation:   " << r.setupTimings.genTagsMs << " ms\n";
    oss << "    Per-iteration (avg / min / max):\n";
    oss << "      Challenge gen:    " << r.avgTimings.genChallengesMs
        << " / " << r.minTimings.genChallengesMs
        << " / " << r.maxTimings.genChallengesMs << " ms\n";
    oss << "      Proof gen:        " << r.avgTimings.genProofsMs
        << " / " << r.minTimings.genProofsMs
        << " / " << r.maxTimings.genProofsMs << " ms\n";
    oss << "      Verification:     " << r.avgTimings.verifyProofsMs
        << " / " << r.minTimings.verifyProofsMs
        << " / " << r.maxTimings.verifyProofsMs << " ms\n";
    if (r.messageSizes.challengeBytes > 0 || r.messageSizes.proofBytes > 0) {
        oss << "    Message sizes:\n";
        oss << "      Challenge:        " << r.messageSizes.challengeBytes << " bytes\n";
        oss << "      Proof:            " << r.messageSizes.proofBytes << " bytes\n";
    }
    return oss.str();
}

/// Common PDP JSON block for one result (timing + message + memory)
std::string pdpCommonJson(const PdpAuditResult& r, const std::string& indent)
{
    std::ostringstream oss;
    oss << indent << "  \"setupTimingsMs\": {\n";
    oss << indent << "    \"initAlgorithm\": " << r.setupTimings.initAlgoMs << ",\n";
    oss << indent << "    \"generateKeys\": " << r.setupTimings.genKeysMs << ",\n";
    oss << indent << "    \"generateTags\": " << r.setupTimings.genTagsMs << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"avgTimingsMs\": {\n";
    oss << indent << "    \"generateChallenges\": " << r.avgTimings.genChallengesMs << ",\n";
    oss << indent << "    \"generateProofs\": " << r.avgTimings.genProofsMs << ",\n";
    oss << indent << "    \"verifyProofs\": " << r.avgTimings.verifyProofsMs << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"minTimingsMs\": {\n";
    oss << indent << "    \"generateChallenges\": " << r.minTimings.genChallengesMs << ",\n";
    oss << indent << "    \"generateProofs\": " << r.minTimings.genProofsMs << ",\n";
    oss << indent << "    \"verifyProofs\": " << r.minTimings.verifyProofsMs << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"maxTimingsMs\": {\n";
    oss << indent << "    \"generateChallenges\": " << r.maxTimings.genChallengesMs << ",\n";
    oss << indent << "    \"generateProofs\": " << r.maxTimings.genProofsMs << ",\n";
    oss << indent << "    \"verifyProofs\": " << r.maxTimings.verifyProofsMs << "\n";
    oss << indent << "  },\n";
    oss << indent << "  \"messageSizes\": {\n";
    oss << indent << "    \"challengeBytes\": " << r.messageSizes.challengeBytes << ",\n";
    oss << indent << "    \"proofBytes\": " << r.messageSizes.proofBytes << "\n";
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
    oss << "\n╔══════════════════════════════════════════════════════════════════╗\n";
    oss << "║     Identity Verification Benchmark Report — " << algorithmType_;
    std::size_t padLen = 19 - algorithmType_.size();
    for (std::size_t i = 0; i < padLen; ++i) oss << ' ';
    oss << "║\n";
    oss << "╚══════════════════════════════════════════════════════════════════╝\n\n";

    oss << "Parameter Descriptions:\n";
    oss << "  Users             — Enrolled users\n";
    oss << "  Samples/Iter      — Verification samples per iteration\n";
    oss << "  Accuracy Rate     — (TP + TN) / total\n";
    oss << "  TP/FP/TN/FN        — True/false accepts/rejects\n\n";

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
    oss << std::string(86, '-') << "\n";

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
        oss << "      Init algorithm:   " << std::fixed << std::setprecision(2)
            << r->setupTimings.initAlgoMs << " ms\n";
        oss << "      Key generation:   " << r->setupTimings.genKeysMs << " ms\n";
        oss << "    Per-iteration (avg / min / max):\n";
        oss << "      Sign:             " << r->avgTimings.signMs
            << " / " << r->minTimings.signMs
            << " / " << r->maxTimings.signMs << " ms\n";
        oss << "      Aggregate verify: " << r->avgTimings.aggregateVerifyMs
            << " / " << r->minTimings.aggregateVerifyMs
            << " / " << r->maxTimings.aggregateVerifyMs << " ms\n";
        if (r->messageSizes.signatureBytes > 0 || r->messageSizes.verifyRequestBytes > 0) {
            oss << "    Message sizes:\n";
            oss << "      Signature:        " << r->messageSizes.signatureBytes << " bytes\n";
            oss << "      Verify request:   " << r->messageSizes.verifyRequestBytes << " bytes\n";
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
        oss << "      \"accuracyRate\": " << std::fixed << std::setprecision(2) << r->accuracyRate << ",\n";
        oss << "      \"trueAccepts\": " << r->trueAccepts << ",\n";
        oss << "      \"falseAccepts\": " << r->falseAccepts << ",\n";
        oss << "      \"trueRejects\": " << r->trueRejects << ",\n";
        oss << "      \"falseRejects\": " << r->falseRejects << ",\n";
        oss << "      \"setupTimingsMs\": {\n";
        oss << "        \"initAlgorithm\": " << r->setupTimings.initAlgoMs << ",\n";
        oss << "        \"generateKeys\": " << r->setupTimings.genKeysMs << "\n";
        oss << "      },\n";
        oss << "      \"avgTimingsMs\": {\n";
        oss << "        \"sign\": " << r->avgTimings.signMs << ",\n";
        oss << "        \"aggregateVerify\": " << r->avgTimings.aggregateVerifyMs << "\n";
        oss << "      },\n";
        oss << "      \"minTimingsMs\": {\n";
        oss << "        \"sign\": " << r->minTimings.signMs << ",\n";
        oss << "        \"aggregateVerify\": " << r->minTimings.aggregateVerifyMs << "\n";
        oss << "      },\n";
        oss << "      \"maxTimingsMs\": {\n";
        oss << "        \"sign\": " << r->maxTimings.signMs << ",\n";
        oss << "        \"aggregateVerify\": " << r->maxTimings.aggregateVerifyMs << "\n";
        oss << "      },\n";
        oss << "      \"messageSizes\": {\n";
        oss << "        \"signatureBytes\": " << r->messageSizes.signatureBytes << ",\n";
        oss << "        \"verifyRequestBytes\": " << r->messageSizes.verifyRequestBytes << "\n";
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
