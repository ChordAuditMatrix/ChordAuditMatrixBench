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
 * @details Formats a DynamicMaintenanceResult into the human-readable console
 *          report and the machine-readable JSON report. Both expose the
 *          operation, per-worker initial block count, success/failure totals,
 *          the aggregated maintenance call timing and the whole-run wall time
 *          with its end-to-end rate — no PDP audit metrics.
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#ifndef CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H
#define CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <string>

namespace CAMatrix::Audit::Benchmark {

/// @brief Stable display name of a maintenance operation
/// @param operation Operation to name
/// @return "Update", "Insert" or "Delete"
/// @throws std::invalid_argument When @p operation is not one of the three
std::string maintenanceOperationName(MaintenanceOperation operation);

/// @brief Renders the aligned console report for a maintenance run
/// @param result Maintenance result to report
/// @return Multi-line console report
std::string dynamicMaintenanceConsoleReport(
    const DynamicMaintenanceResult& result);

/// @brief Renders the indented JSON report for a maintenance run
/// @param result Maintenance result to report
/// @return JSON document terminated by a newline
std::string dynamicMaintenanceJsonReport(
    const DynamicMaintenanceResult& result);

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_DYNAMIC_MAINTENANCE_REPORT_H
