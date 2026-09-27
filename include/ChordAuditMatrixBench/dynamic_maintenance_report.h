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
 * @file dynamic_maintenance_report.h
 * @brief Console/JSON reporting for the dynamic maintenance benchmark
 * @details Renders a DynamicMaintenanceResult through the framework's Report
 *          interface — the same polymorphic contract as the PDP and identity
 *          reports — so the maintenance CLI prints and serialises results
 *          through Report::toConsole()/Report::toJson() like every other
 *          benchmark. Both outputs expose the operation, per-worker initial
 *          block count, success/failure totals, the aggregated maintenance call
 *          timing and the whole-run wall time with its end-to-end rate — no PDP
 *          audit metrics.
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#ifndef CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H
#define CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H

#include <ChordAuditMatrixBench/benchmark_report.h>
#include <ChordAuditMatrixBench/benchmark_types.h>

#include <string>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class DynamicMaintenanceReport
 * @brief Report for the dynamic maintenance strategy
 * @details Formats the single DynamicMaintenanceResult of a maintenance run:
 *          operation, per-worker initial block count, call totals, aggregated
 *          maintenance timing and the whole-run wall time / end-to-end
 *          throughput. The result is referenced, not copied — it must outlive
 *          the report.
 */
class DynamicMaintenanceReport final : public Report {
public:
    /**
     * @brief Construct a maintenance report for one result
     * @param result Maintenance result to report
     */
    explicit DynamicMaintenanceReport(const DynamicMaintenanceResult& result)
        : result_(result)
    {}

    /// @brief Render the aligned console report
    /// @return Multi-line console report
    std::string toConsole() const override;

    /// @brief Render the indented JSON report
    /// @return JSON document terminated by a newline
    std::string toJson() const override;

private:
    const DynamicMaintenanceResult& result_; /**< Result being reported (not owned) */
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H
