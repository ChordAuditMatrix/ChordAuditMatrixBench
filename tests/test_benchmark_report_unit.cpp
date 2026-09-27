/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * @file test_benchmark_report_unit.cpp
 * @brief Tests for the polymorphic Report hierarchy, maintenance report included.
 * @details Owned by the Bench repository (no algorithm plugin involved): every
 *          concrete report — the three PDP reports, the identity report and the
 *          dynamic maintenance report — renders through the same Report
 *          interface, and the maintenance report's console/JSON contract
 *          (operation, call totals, timing, whole-run rate, no PDP fields) is
 *          frozen here.
 */

#include <ChordAuditMatrixBench/benchmark_report.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/dynamic_maintenance_report.h>

#include <gtest/gtest.h>
#include <json/json.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Benchmark {
namespace {

/// Build a maintenance result with fully determined report inputs.
DynamicMaintenanceResult makeMaintenanceResult(MaintenanceOperation operation)
{
    DynamicMaintenanceResult result;
    result.algorithmType = "DHTDynamic";
    result.operation = operation;
    result.initialBlocks = 4;
    result.iterations = 4;
    result.requestedThreads = 2;
    result.effectiveThreads = 2;
    result.successfulOperations = 3;
    result.failedOperations = 1;
    result.finalBlocksAcrossWorkerStores = 6;
    result.wallTimeMs = 250.0;
    result.iterationTimings.maintain.totalMs = 40.0;
    result.iterationTimings.maintain.callCount = 4;
    result.iterationTimings.maintain.averageMs = 10.0;
    result.setupTimings.initAlgorithm.totalMs = 5.0;
    result.setupTimings.initAlgorithm.callCount = 2;
    result.setupTimings.generateKeys.totalMs = 7.0;
    result.setupTimings.generateKeys.callCount = 2;
    return result;
}

Json::Value parseJson(const std::string& json)
{
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value root;
    std::string errors;
    EXPECT_TRUE(reader->parse(json.data(), json.data() + json.size(), &root, &errors))
        << errors;
    return root;
}

// ============================================================================
// One interface, five reports
// ============================================================================

TEST(BenchmarkReportTest, EveryReportRendersThroughTheReportInterface)
{
    auto pdpResult = std::make_unique<PdpAuditResult>();
    pdpResult->algorithmType = "SM9Static";
    pdpResult->totalBlocks = 8;
    pdpResult->corruptedBlocks = 2;
    pdpResult->sampleSize = 3;
    pdpResult->iterations = 4;
    pdpResult->detections = 3;
    pdpResult->confidenceRate = 0.75;

    auto identityResult = std::make_unique<IdentityResult>();
    identityResult->algorithmType = "SM9Noncert";
    identityResult->iterations = 2;
    identityResult->numUsers = 3;
    identityResult->totalVerifySamples = 6;
    identityResult->trueAccepts = 6;
    identityResult->accuracyRate = 1.0;

    ResultVec pdpResults;
    pdpResults.push_back(std::move(pdpResult));
    ResultVec identityResults;
    identityResults.push_back(std::move(identityResult));
    const DynamicMaintenanceResult maintenance = makeMaintenanceResult(MaintenanceOperation::Insert);

    std::vector<std::pair<std::string, std::unique_ptr<Report>>> reports;
    reports.emplace_back("SM9Static", std::make_unique<PdpDirectReport>(pdpResults, "SM9Static"));
    reports.emplace_back("SM9Static", std::make_unique<PdpFixedRatioReport>(pdpResults, "SM9Static"));
    reports.emplace_back("SM9Static", std::make_unique<PdpInverseConfidenceReport>(pdpResults, "SM9Static"));
    reports.emplace_back("SM9Noncert", std::make_unique<IdentityReport>(identityResults, "SM9Noncert"));
    reports.emplace_back("DHTDynamic", std::make_unique<DynamicMaintenanceReport>(maintenance));

    ASSERT_EQ(reports.size(), 5U);
    for (const auto& entry : reports) {
        const std::string console = entry.second->toConsole();
        const std::string json = entry.second->toJson();
        EXPECT_FALSE(console.empty());
        EXPECT_FALSE(json.empty());
        // Each report labels its own results; all of them are reachable through
        // the same Report interface.
        EXPECT_NE(console.find(entry.first), std::string::npos);
        EXPECT_TRUE(parseJson(json).isObject());
    }
}

// ============================================================================
// DynamicMaintenanceReport console/JSON contract
// ============================================================================

TEST(DynamicMaintenanceReportTest, ConsoleShowsOperationTotalsTimingAndWholeRunRate)
{
    const DynamicMaintenanceResult result = makeMaintenanceResult(MaintenanceOperation::Update);
    const DynamicMaintenanceReport report(result);

    const std::string console = report.toConsole();

    EXPECT_NE(console.find("Dynamic Maintenance Benchmark: DHTDynamic"), std::string::npos);
    EXPECT_NE(console.find("Update"), std::string::npos);
    EXPECT_NE(console.find("Successful operations:"), std::string::npos);
    EXPECT_NE(console.find("Failed operations:"), std::string::npos);
    EXPECT_NE(console.find("Total maintenance time:"), std::string::npos);
    EXPECT_NE(console.find("Final blocks (all workers):"), std::string::npos);
    EXPECT_NE(console.find("Wall time (end-to-end):"), std::string::npos);
    EXPECT_NE(console.find("End-to-end throughput:"), std::string::npos);
    // 3 successful operations over 250 ms of whole-run wall time.
    EXPECT_NE(console.find("12.00 ops/s"), std::string::npos);
    EXPECT_DOUBLE_EQ(result.endToEndOperationsPerSecond(), 12.0);
}

TEST(DynamicMaintenanceReportTest, JsonExposesTheRunSchemaAndNoPdpFields)
{
    const DynamicMaintenanceResult result = makeMaintenanceResult(MaintenanceOperation::Delete);
    const DynamicMaintenanceReport report(result);

    const Json::Value root = parseJson(report.toJson());

    EXPECT_EQ(root["algorithmType"].asString(), "DHTDynamic");
    EXPECT_EQ(root["operation"].asString(), "Delete");
    EXPECT_EQ(root["initialBlocksPerWorker"].asUInt64(), 4U);
    EXPECT_EQ(root["iterations"].asUInt64(), 4U);
    EXPECT_EQ(root["requestedThreads"].asUInt64(), 2U);
    EXPECT_EQ(root["effectiveThreads"].asUInt64(), 2U);
    EXPECT_EQ(root["successfulOperations"].asUInt64(), 3U);
    EXPECT_EQ(root["failedOperations"].asUInt64(), 1U);
    EXPECT_EQ(root["finalBlocksAcrossWorkerStores"].asUInt64(), 6U);
    EXPECT_EQ(root["maintenanceTiming"]["callCount"].asUInt64(), 4U);
    EXPECT_DOUBLE_EQ(root["maintenanceTiming"]["totalMs"].asDouble(), 40.0);
    EXPECT_DOUBLE_EQ(root["maintenanceTiming"]["averageMs"].asDouble(), 10.0);
    EXPECT_DOUBLE_EQ(root["wallTimeMs"].asDouble(), 250.0);
    EXPECT_DOUBLE_EQ(root["endToEndOperationsPerSecond"].asDouble(), 12.0);
    EXPECT_EQ(root["setupTimings"]["initAlgorithm"]["callCount"].asUInt64(), 2U);
    EXPECT_EQ(root["setupTimings"]["generateKeys"]["callCount"].asUInt64(), 2U);
    // Maintenance results carry no PDP audit data.
    EXPECT_FALSE(root.isMember("confidenceRate"));
    EXPECT_FALSE(root.isMember("detections"));
}

TEST(DynamicMaintenanceReportTest, JsonNamesEveryOperation)
{
    for (const auto& entry : {std::make_pair(MaintenanceOperation::Update, "Update"),
                              std::make_pair(MaintenanceOperation::Insert, "Insert"),
                              std::make_pair(MaintenanceOperation::Delete, "Delete")}) {
        const DynamicMaintenanceResult result = makeMaintenanceResult(entry.first);
        const Json::Value root = parseJson(DynamicMaintenanceReport(result).toJson());
        EXPECT_EQ(root["operation"].asString(), entry.second);
    }
}

} // namespace
} // namespace CAMatrix::Audit::Benchmark
