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
 * @file benchmark_report.h
 * @brief Report generation for benchmark results (PDP audit + identity verification)
 * @details Provides human-readable console output and machine-readable
 *          JSON output for benchmark results. Dispatches on ResultKind to
 *          format PDP audit results (confidence rate) or identity verification
 *          results (accuracy rate + confusion matrix) appropriately.
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_REPORT_H
#define CAMATRIX_AUDIT_BENCHMARK_REPORT_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class BenchmarkReport
 * @brief Static utility class for generating benchmark reports
 * @details Supports both PDP audit and identity verification result formats.
 *          Dispatches on ResultKind to produce scenario-appropriate output.
 */
class BenchmarkReport {
public:
    BenchmarkReport() = delete;

    // ── Console report ──

    /**
     * @brief Generate a human-readable console report
     * @param results Vector of benchmark results
     * @param algorithmType Algorithm type identifier
     * @return Formatted report string
     */
    static std::string toConsole(const std::vector<BenchmarkResult>& results,
                                  const std::string& algorithmType)
    {
        if (results.empty()) return "(no results)\n";

        const auto resultKind = results.front().resultKind;
        if (resultKind == ResultKind::PdpAudit) {
            return pdpConsoleReport(results, algorithmType);
        } else {
            return identityConsoleReport(results, algorithmType);
        }
    }

    // ── JSON report ──

    /**
     * @brief Generate a machine-readable JSON report
     * @param results Vector of benchmark results
     * @param algorithmType Algorithm type identifier
     * @return JSON-formatted report string
     */
    static std::string toJson(const std::vector<BenchmarkResult>& results,
                               const std::string& algorithmType)
    {
        if (results.empty()) {
            return "{ \"algorithmType\": \"" + algorithmType + "\", \"results\": [] }\n";
        }

        const auto resultKind = results.front().resultKind;
        if (resultKind == ResultKind::PdpAudit) {
            return pdpJsonReport(results, algorithmType);
        } else {
            return identityJsonReport(results, algorithmType);
        }
    }

private:
    // ══════════════════════════════════════════════════════════════════
    // PDP Audit Report
    // ══════════════════════════════════════════════════════════════════

    /**
     * @brief Generate PDP audit console report
     * @param results Vector of PDP audit benchmark results
     * @param algorithmType Algorithm type identifier
     * @return Formatted console string
     */
    static std::string pdpConsoleReport(const std::vector<BenchmarkResult>& results,
                                         const std::string& algorithmType)
    {
        std::ostringstream oss;
        oss << "\n╔══════════════════════════════════════════════════════════════════╗\n";
        oss << "║          Audit Benchmark Report — " << algorithmType;
        std::size_t padLen = 32 - algorithmType.size();
        for (std::size_t i = 0; i < padLen; ++i) oss << ' ';
        oss << "║\n";
        oss << "╚══════════════════════════════════════════════════════════════════╝\n\n";

        // Parameter descriptions
        oss << "Parameter Descriptions:\n";
        oss << "  N (totalBlocks)    — Total number of data blocks in the dataset\n";
        oss << "  t (corruptedBlocks)— Number of data blocks whose content was modified (data-tag mismatch)\n";
        oss << "  r (sampleSize)     — Number of blocks randomly sampled per audit iteration\n";
        oss << "  Confidence Rate    — Ratio of iterations detecting data incompleteness to total iterations\n";
        oss << "  Theoretical Rate   — Hypergeometric probability: 1 - C(N-t,r)/C(N,r)\n\n";

        // Results table
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

        for (const auto& r : results) {
            oss << std::left
                << std::setw(8)  << r.totalBlocks
                << std::setw(8)  << r.corruptedBlocks
                << std::setw(8)  << r.sampleSize
                << std::setw(12) << r.iterations
                << std::setw(16) << r.detections
                << std::setw(16) << std::fixed << std::setprecision(2) << r.confidenceRate
                << std::setw(16) << std::fixed << std::setprecision(2) << r.theoreticalConfidenceRate
                << "\n";
        }

        // Performance summary
        oss << "\n── Performance Summary ──\n";
        for (const auto& r : results) {
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
        }

        return oss.str();
    }

    /**
     * @brief Generate PDP audit JSON report
     * @param results Vector of PDP audit benchmark results
     * @param algorithmType Algorithm type identifier
     * @return JSON-formatted string
     */
    static std::string pdpJsonReport(const std::vector<BenchmarkResult>& results,
                                      const std::string& algorithmType)
    {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"resultKind\": \"PdpAudit\",\n";
        oss << "  \"algorithmType\": \"" << algorithmType << "\",\n";
        oss << "  \"parameterDescriptions\": {\n";
        oss << "    \"N\": \"Total number of data blocks in the dataset\",\n";
        oss << "    \"t\": \"Number of data blocks whose content was modified (data-tag mismatch)\",\n";
        oss << "    \"r\": \"Number of blocks randomly sampled per audit iteration\",\n";
        oss << "    \"confidenceRate\": \"Ratio of iterations detecting data incompleteness to total iterations\"\n";
        oss << "  },\n";
        oss << "  \"results\": [\n";

        for (std::size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            oss << "    {\n";
            oss << "      \"totalBlocks\": " << r.totalBlocks << ",\n";
            oss << "      \"corruptedBlocks\": " << r.corruptedBlocks << ",\n";
            oss << "      \"sampleSize\": " << r.sampleSize << ",\n";
            oss << "      \"iterations\": " << r.iterations << ",\n";
            oss << "      \"detections\": " << r.detections << ",\n";
            oss << "      \"confidenceRate\": " << std::fixed << std::setprecision(2) << r.confidenceRate << ",\n";
            oss << "      \"theoreticalConfidenceRate\": " << std::fixed << std::setprecision(2) << r.theoreticalConfidenceRate << ",\n";
            oss << "      \"setupTimingsMs\": {\n";
            oss << "        \"initAlgorithm\": " << r.setupTimings.initAlgoMs << ",\n";
            oss << "        \"generateKeys\": " << r.setupTimings.genKeysMs << ",\n";
            oss << "        \"generateTags\": " << r.setupTimings.genTagsMs << "\n";
            oss << "      },\n";
            oss << "      \"avgTimingsMs\": {\n";
            oss << "        \"generateChallenges\": " << r.avgTimings.genChallengesMs << ",\n";
            oss << "        \"generateProofs\": " << r.avgTimings.genProofsMs << ",\n";
            oss << "        \"verifyProofs\": " << r.avgTimings.verifyProofsMs << "\n";
            oss << "      },\n";
            oss << "      \"minTimingsMs\": {\n";
            oss << "        \"generateChallenges\": " << r.minTimings.genChallengesMs << ",\n";
            oss << "        \"generateProofs\": " << r.minTimings.genProofsMs << ",\n";
            oss << "        \"verifyProofs\": " << r.minTimings.verifyProofsMs << "\n";
            oss << "      },\n";
            oss << "      \"maxTimingsMs\": {\n";
            oss << "        \"generateChallenges\": " << r.maxTimings.genChallengesMs << ",\n";
            oss << "        \"generateProofs\": " << r.maxTimings.genProofsMs << ",\n";
            oss << "        \"verifyProofs\": " << r.maxTimings.verifyProofsMs << "\n";
            oss << "      },\n";
            oss << "      \"messageSizes\": {\n";
            oss << "        \"challengeBytes\": " << r.messageSizes.challengeBytes << ",\n";
            oss << "        \"proofBytes\": " << r.messageSizes.proofBytes << "\n";
            oss << "      },\n";
            oss << "      \"memoryPeakBytes\": " << r.memoryPeakBytes << "\n";
            oss << "    }";
            if (i + 1 < results.size()) oss << ",";
            oss << "\n";
        }

        oss << "  ]\n";
        oss << "}\n";
        return oss.str();
    }

    // ══════════════════════════════════════════════════════════════════
    // Identity Verification Report
    // ══════════════════════════════════════════════════════════════════

    /**
     * @brief Generate identity verification console report
     * @param results Vector of identity verification benchmark results
     * @param algorithmType Algorithm type identifier
     * @return Formatted console string
     */
    static std::string identityConsoleReport(const std::vector<BenchmarkResult>& results,
                                              const std::string& algorithmType)
    {
        std::ostringstream oss;
        oss << "\n╔══════════════════════════════════════════════════════════════════╗\n";
        oss << "║     Identity Verification Benchmark Report — " << algorithmType;
        std::size_t padLen = 19 - algorithmType.size();
        for (std::size_t i = 0; i < padLen; ++i) oss << ' ';
        oss << "║\n";
        oss << "╚══════════════════════════════════════════════════════════════════╝\n\n";

        // Parameter descriptions
        oss << "Parameter Descriptions:\n";
        oss << "  Users             — Number of enrolled users in the identity system\n";
        oss << "  Samples/Iter      — Number of verification samples per iteration\n";
        oss << "  Accuracy Rate     — (TP + TN) / (TP + FP + TN + FN)\n";
        oss << "  TP (True Accept)  — Legitimate signature correctly accepted\n";
        oss << "  FP (False Accept) — Forged signature incorrectly accepted\n";
        oss << "  TN (True Reject)  — Forged signature correctly rejected\n";
        oss << "  FN (False Reject) — Legitimate signature incorrectly rejected\n\n";

        // Results table
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

        for (const auto& r : results) {
            oss << std::left
                << std::setw(8)  << r.numUsers
                << std::setw(12) << r.totalVerifySamples
                << std::setw(12) << r.iterations
                << std::fixed << std::setprecision(2)
                << std::setw(14) << r.accuracyRate
                << std::setw(10) << r.trueAccepts
                << std::setw(10) << r.falseAccepts
                << std::setw(10) << r.trueRejects
                << std::setw(10) << r.falseRejects
                << "\n";
        }

        // Performance summary
        oss << "\n── Performance Summary ──\n";
        for (const auto& r : results) {
            oss << "  Users=" << r.numUsers
                << " Samples=" << r.totalVerifySamples << ":\n";
            oss << "    Setup (one-time):\n";
            oss << "      Init algorithm:   " << std::fixed << std::setprecision(2)
                << r.setupTimings.initAlgoMs << " ms\n";
            oss << "      Key generation:   " << r.setupTimings.genKeysMs << " ms\n";
            oss << "    Per-iteration (avg / min / max):\n";
            oss << "      Sign:             " << r.avgTimings.signMs
                << " / " << r.minTimings.signMs
                << " / " << r.maxTimings.signMs << " ms\n";
            oss << "      Aggregate verify: " << r.avgTimings.aggregateVerifyMs
                << " / " << r.minTimings.aggregateVerifyMs
                << " / " << r.maxTimings.aggregateVerifyMs << " ms\n";
            if (r.messageSizes.signatureBytes > 0 || r.messageSizes.verifyRequestBytes > 0) {
                oss << "    Message sizes:\n";
                oss << "      Signature:        " << r.messageSizes.signatureBytes << " bytes\n";
                oss << "      Verify request:   " << r.messageSizes.verifyRequestBytes << " bytes\n";
            }
            oss << "    Confusion Matrix:\n";
            oss << "                    Predicted Accept  Predicted Reject\n";
            oss << "      Actual Accept   TP=" << r.trueAccepts
                << "          FN=" << r.falseRejects << "\n";
            oss << "      Actual Reject   FP=" << r.falseAccepts
                << "          TN=" << r.trueRejects << "\n";
        }

        return oss.str();
    }

    /**
     * @brief Generate identity verification JSON report
     * @param results Vector of identity verification benchmark results
     * @param algorithmType Algorithm type identifier
     * @return JSON-formatted string
     */
    static std::string identityJsonReport(const std::vector<BenchmarkResult>& results,
                                           const std::string& algorithmType)
    {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"resultKind\": \"IdentityVerification\",\n";
        oss << "  \"algorithmType\": \"" << algorithmType << "\",\n";
        oss << "  \"parameterDescriptions\": {\n";
        oss << "    \"users\": \"Number of enrolled users in the identity system\",\n";
        oss << "    \"samplesPerIteration\": \"Number of verification samples per iteration\",\n";
        oss << "    \"accuracyRate\": \"(TP + TN) / (TP + FP + TN + FN)\",\n";
        oss << "    \"trueAccepts\": \"Legitimate signature correctly accepted\",\n";
        oss << "    \"falseAccepts\": \"Forged signature incorrectly accepted\",\n";
        oss << "    \"trueRejects\": \"Forged signature correctly rejected\",\n";
        oss << "    \"falseRejects\": \"Legitimate signature incorrectly rejected\"\n";
        oss << "  },\n";
        oss << "  \"results\": [\n";

        for (std::size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            oss << "    {\n";
            oss << "      \"numUsers\": " << r.numUsers << ",\n";
            oss << "      \"totalVerifySamples\": " << r.totalVerifySamples << ",\n";
            oss << "      \"iterations\": " << r.iterations << ",\n";
            oss << "      \"accuracyRate\": " << std::fixed << std::setprecision(2) << r.accuracyRate << ",\n";
            oss << "      \"trueAccepts\": " << r.trueAccepts << ",\n";
            oss << "      \"falseAccepts\": " << r.falseAccepts << ",\n";
            oss << "      \"trueRejects\": " << r.trueRejects << ",\n";
            oss << "      \"falseRejects\": " << r.falseRejects << ",\n";
            oss << "      \"setupTimingsMs\": {\n";
            oss << "        \"initAlgorithm\": " << r.setupTimings.initAlgoMs << ",\n";
            oss << "        \"generateKeys\": " << r.setupTimings.genKeysMs << "\n";
            oss << "      },\n";
            oss << "      \"avgTimingsMs\": {\n";
            oss << "        \"sign\": " << r.avgTimings.signMs << ",\n";
            oss << "        \"aggregateVerify\": " << r.avgTimings.aggregateVerifyMs << "\n";
            oss << "      },\n";
            oss << "      \"minTimingsMs\": {\n";
            oss << "        \"sign\": " << r.minTimings.signMs << ",\n";
            oss << "        \"aggregateVerify\": " << r.minTimings.aggregateVerifyMs << "\n";
            oss << "      },\n";
            oss << "      \"maxTimingsMs\": {\n";
            oss << "        \"sign\": " << r.maxTimings.signMs << ",\n";
            oss << "        \"aggregateVerify\": " << r.maxTimings.aggregateVerifyMs << "\n";
            oss << "      },\n";
            oss << "      \"messageSizes\": {\n";
            oss << "        \"signatureBytes\": " << r.messageSizes.signatureBytes << ",\n";
            oss << "        \"verifyRequestBytes\": " << r.messageSizes.verifyRequestBytes << "\n";
            oss << "      },\n";
            oss << "      \"memoryPeakBytes\": " << r.memoryPeakBytes << "\n";
            oss << "    }";
            if (i + 1 < results.size()) oss << ",";
            oss << "\n";
        }

        oss << "  ]\n";
        oss << "}\n";
        return oss.str();
    }
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_REPORT_H
