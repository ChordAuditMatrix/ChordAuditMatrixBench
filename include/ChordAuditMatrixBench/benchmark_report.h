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
 * @brief Polymorphic report hierarchy for benchmark results
 * @details Defines a Report base class with virtual toConsole()/toJson() and
 *          concrete subclasses: PdpDirectReport, PdpFixedRatioReport,
 *          PdpInverseConfidenceReport, IdentityReport. PDP reports share a
 *          PdpReportBase helper that extracts PdpAuditResult* pointers from the
 *          polymorphic result vector. The legacy static BenchmarkReport class
 *          with ResultKind dispatch has been removed.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_REPORT_H
#define CAMATRIX_AUDIT_BENCHMARK_REPORT_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <memory>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class Report
 * @brief Polymorphic base for benchmark reports
 */
class Report {
public:
    virtual ~Report() = default;
    /// @brief Human-readable console output
    virtual std::string toConsole() const = 0;
    /// @brief Machine-readable JSON output
    virtual std::string toJson() const = 0;
};

// Forward declaration of the strategy factory's result vector alias
using ResultVec = std::vector<std::unique_ptr<BenchmarkResult>>;

/**
 * @class PdpReportBase
 * @brief Shared base for PDP reports — extracts PdpAuditResult* from results
 */
class PdpReportBase : public Report {
protected:
    std::vector<const PdpAuditResult*> pdpResults_;
    std::string algorithmType_;
public:
    PdpReportBase(const ResultVec& results, const std::string& algorithmType)
        : algorithmType_(algorithmType)
    {
        pdpResults_.reserve(results.size());
        for (const auto& r : results)
            pdpResults_.push_back(dynamic_cast<const PdpAuditResult*>(r.get()));
    }
};

/**
 * @class PdpDirectReport
 * @brief Report for the PdpDirect strategy (fixed N, scan t/r)
 */
class PdpDirectReport : public PdpReportBase {
public:
    using PdpReportBase::PdpReportBase;
    std::string toConsole() const override;
    std::string toJson() const override;
};

/**
 * @class PdpFixedRatioReport
 * @brief Report for the PdpFixedRatio strategy (fixed t/N, r/N, scan N)
 */
class PdpFixedRatioReport : public PdpReportBase {
public:
    using PdpReportBase::PdpReportBase;
    std::string toConsole() const override;
    std::string toJson() const override;
};

/**
 * @class PdpInverseConfidenceReport
 * @brief Report for the PdpInverseConfidence strategy (target P*, scan N)
 */
class PdpInverseConfidenceReport : public PdpReportBase {
public:
    using PdpReportBase::PdpReportBase;
    std::string toConsole() const override;
    std::string toJson() const override;
};

/**
 * @class IdentityReport
 * @brief Report for the IdentityVerify strategy
 */
class IdentityReport : public Report {
    std::vector<const IdentityResult*> identityResults_;
    std::string algorithmType_;
public:
    IdentityReport(const ResultVec& results, const std::string& algorithmType)
        : algorithmType_(algorithmType)
    {
        identityResults_.reserve(results.size());
        for (const auto& r : results)
            identityResults_.push_back(dynamic_cast<const IdentityResult*>(r.get()));
    }
    std::string toConsole() const override;
    std::string toJson() const override;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_REPORT_H
