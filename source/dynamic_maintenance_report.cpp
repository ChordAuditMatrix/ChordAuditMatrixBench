#include <ChordAuditMatrixBench/dynamic_maintenance_report.h>

#include <json/json.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace CAMatrix::Audit::Benchmark {
namespace {

/// Stable display name of a maintenance operation.
std::string maintenanceOperationName(MaintenanceOperation operation)
{
    switch (operation) {
        case MaintenanceOperation::Update: return "Update";
        case MaintenanceOperation::Insert: return "Insert";
        case MaintenanceOperation::Delete: return "Delete";
    }
    throw std::invalid_argument("Unknown maintenance operation");
}

Json::Value timingJson(const TimingMetric& metric)
{
    Json::Value value(Json::objectValue);
    value["totalMs"] = metric.totalMs;
    value["averageMs"] = metric.averageMs;
    value["callCount"] = static_cast<Json::UInt64>(metric.callCount);
    return value;
}

Json::Value reportJson(const DynamicMaintenanceResult& result)
{
    Json::Value root(Json::objectValue);
    root["algorithmType"] = result.algorithmType;
    root["operation"] = maintenanceOperationName(result.operation);
    root["initialBlocksPerWorker"] = static_cast<Json::UInt64>(result.initialBlocks);
    root["iterations"] = static_cast<Json::UInt64>(result.iterations);
    root["requestedThreads"] = static_cast<Json::UInt64>(result.requestedThreads);
    root["effectiveThreads"] = static_cast<Json::UInt64>(result.effectiveThreads);
    root["successfulOperations"] = static_cast<Json::UInt64>(result.successfulOperations);
    root["failedOperations"] = static_cast<Json::UInt64>(result.failedOperations);
    root["finalBlocksAcrossWorkerStores"] =
        static_cast<Json::UInt64>(result.finalBlocksAcrossWorkerStores);
    // Per-call latency aggregates every worker's maintenance calls; the wall
    // time and the end-to-end rate that use it cover the whole runner
    // lifecycle (setup + iterations + teardown), not maintenance alone.
    root["maintenanceTiming"] = timingJson(result.iterationTimings.maintain);
    root["wallTimeMs"] = result.wallTimeMs;
    root["endToEndOperationsPerSecond"] = result.endToEndOperationsPerSecond();
    root["setupTimings"]["initAlgorithm"] = timingJson(result.setupTimings.initAlgorithm);
    root["setupTimings"]["generateKeys"] = timingJson(result.setupTimings.generateKeys);
    return root;
}

} // namespace

std::string DynamicMaintenanceReport::toConsole() const
{
    const auto& maintenance = result_.iterationTimings.maintain;
    const auto& initAlgorithm = result_.setupTimings.initAlgorithm;
    const auto& generateKeys = result_.setupTimings.generateKeys;

    std::ostringstream out;
    out << "Dynamic Maintenance Benchmark: " << result_.algorithmType << '\n';
    // One label column for every line, then the value; numeric values keep the
    // stream's fixed precision (4 decimals for times, 2 for the rate).
    out << std::left << std::fixed << std::setprecision(4);
    out << std::setw(28) << "  Operation:" << maintenanceOperationName(result_.operation) << '\n';
    out << std::setw(28) << "  Initial blocks per worker:" << result_.initialBlocks << '\n';
    out << std::setw(28) << "  Iterations:" << result_.iterations << '\n';
    out << std::setw(28) << "  Threads:"
        << std::to_string(result_.effectiveThreads) + " effective, "
               + std::to_string(result_.requestedThreads) + " requested" << '\n';
    out << std::setw(28) << "  Successful operations:" << result_.successfulOperations << '\n';
    out << std::setw(28) << "  Failed operations:" << result_.failedOperations << '\n';
    out << std::setw(28) << "  Final blocks (all workers):"
        << result_.finalBlocksAcrossWorkerStores << '\n';
    out << std::setw(28) << "  Total maintenance time:"
        << maintenance.totalMs << " ms (" << maintenance.callCount
        << " calls, aggregated across workers)\n";
    out << std::setw(28) << "  Average maintenance call:"
        << maintenance.averageMs << " ms\n";
    out << std::setw(28) << "  Setup initAlgorithm:"
        << initAlgorithm.totalMs << " ms (" << initAlgorithm.callCount << " calls)\n";
    out << std::setw(28) << "  Setup generateKeys:"
        << generateKeys.totalMs << " ms (" << generateKeys.callCount << " calls)\n";
    out << std::setw(28) << "  Wall time (end-to-end):" << result_.wallTimeMs << " ms\n";
    out << std::setw(28) << "  End-to-end throughput:"
        << std::setprecision(2) << result_.endToEndOperationsPerSecond()
        << " ops/s (successful ops / whole-run wall time, includes setup)\n";
    return out.str();
}

std::string DynamicMaintenanceReport::toJson() const
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    return Json::writeString(builder, reportJson(result_)) + "\n";
}

} // namespace CAMatrix::Audit::Benchmark
