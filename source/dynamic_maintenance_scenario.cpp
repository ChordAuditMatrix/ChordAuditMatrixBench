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
 * @file dynamic_maintenance_scenario.cpp
 * @brief Dynamic maintenance benchmark scenario implementation
 * @details Concrete BenchmarkScenario for dynamic PDP maintenance: one
 *          Update/Insert/Delete call per iteration against the worker-local
 *          StateStore of a dynamic strategy.
 *
 *          Lifecycle of one worker (one scenario instance, one runner slot):
 *          - setup(): resolve the strategy, create the worker's own engine,
 *            initialize the algorithm, generate keys and build a StateStore
 *            pre-filled with initialBlocks blocks; the operation context keeps
 *            that engine + strategy + StateStore worker-local.
 *          - prepare(): no-op — the maintenance benchmark needs no corruption.
 *          - runIteration(): one maintenance call on a legal 1-based block
 *            index (Update: round-robin over the initial blocks; Insert: the
 *            append slot count + 1; Delete: the current last block). A failed
 *            call is counted, not thrown, so a run reports success/failure
 *            totals instead of aborting on the first rejected operation.
 *          - teardown(): drop engine/context/StateStore.
 *
 *          The strategy instance is shared read-only across workers (resolved
 *          from the AuditStrategyManager), while engine, context and StateStore
 *          are per worker — so iterations are independent and the runner may
 *          partition them (see supportsParallelIterations()). Delete configs
 *          are rejected in setup() when any worker's delete range could exhaust
 *          its store (initialBlocks < max iterations of a single worker).
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#include <ChordAuditMatrixBench/dynamic_maintenance_scenario.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include <ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h>
#include <ChordAuditMatrixLib/interfaces/audit/messages/request_result.h>
#include <ChordAuditMatrixLib/interfaces/audit/strategy.h>

#include <json/json.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace CAMatrix::Audit::Benchmark {
namespace {

using namespace CAMatrix::Audit;

Messages::RawInput jsonInput(const Json::Value& value)
{
    return Messages::RawInput(
        std::make_shared<std::string>(Json::FastWriter().write(value)));
}

/// Adds one measured call to a metric: sums the elapsed time, counts the call
/// and recomputes the average from the accumulated totals.
void accumulateTiming(TimingMetric& metric,
                      std::chrono::steady_clock::time_point start)
{
    metric.totalMs += std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
    ++metric.callCount;
    metric.averageMs = metric.totalMs / static_cast<double>(metric.callCount);
}

/// Times one action into @p metric; a throwing action still counts as a call.
template<class F>
void measure(TimingMetric& metric, F&& action)
{
    const auto start = std::chrono::steady_clock::now();
    try {
        action();
    } catch (...) {
        accumulateTiming(metric, start);
        throw;
    }
    accumulateTiming(metric, start);
}

/// Mirrors the BenchmarkRunner iteration split: requested threads (0 = the
/// hardware concurrency the runner resolves), clamped to the iteration count,
/// then the balanced slot sizes — the largest slot is what a single worker can
/// be asked to execute.
std::size_t maximumWorkerIterations(const BenchmarkConfig& config)
{
    const auto hardware = std::thread::hardware_concurrency();
    const std::size_t requested = config.threads == 0
        ? (hardware == 0 ? 1 : hardware)
        : config.threads;
    const std::size_t effective = std::min(
        requested, std::max<std::size_t>(config.iterations, 1));
    return config.iterations / effective
        + (config.iterations % effective != 0 ? 1 : 0);
}

} // namespace

DynamicMaintenanceScenario::DynamicMaintenanceScenario(
    std::string algorithmType,
    std::shared_ptr<Core::AuditStrategyManager> strategyManager)
    : algorithmType_(std::move(algorithmType))
    , strategyManager_(std::move(strategyManager))
{
    if (!strategyManager_) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario: strategy manager must not be null");
    }
}

/// One run's iterations are independent maintenance calls against
/// worker-local state, so they partition across workers whenever the manager
/// resolves a dynamic strategy: each worker's scenario creates its own engine,
/// context and StateStore. A missing or non-dynamic strategy reports false so
/// the runner stays serial and setup() then rejects the config with a clear
/// error instead of spawning workers that would all fail.
bool DynamicMaintenanceScenario::supportsParallelIterations() const
{
    if (!strategyManager_ || !strategyManager_->hasAlgorithm(algorithmType_)) {
        return false;
    }
    const auto strategy = strategyManager_->getStrategy(algorithmType_);
    return strategy && strategy->kind() == Core::StrategyKind::Dynamic;
}

std::string DynamicMaintenanceScenario::algorithmType() const
{
    return algorithmType_;
}

void DynamicMaintenanceScenario::setup(const BenchmarkConfig& config)
{
    const auto* maintenanceConfig =
        dynamic_cast<const DynamicMaintenanceConfig*>(&config);
    if (!maintenanceConfig) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario requires a DynamicMaintenanceConfig");
    }
    config_ = *maintenanceConfig;
    if (config_.initialBlocks == 0) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario: initialBlocks must be greater than zero");
    }
    // Delete consumes one existing block per iteration, so every worker's
    // delete range must fit inside that worker's own store. The runner splits
    // the iterations into balanced contiguous slots; the largest slot is what
    // bounds the capacity check below.
    const std::size_t largestWorkerRange = maximumWorkerIterations(config_);
    if (config_.operation == MaintenanceOperation::Delete
        && config_.initialBlocks < largestWorkerRange) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario: initialBlocks (" +
            std::to_string(config_.initialBlocks) +
            ") is smaller than the largest worker delete range (" +
            std::to_string(largestWorkerRange) +
            "); raise --initial-blocks or lower --iterations/--threads");
    }
    if (!strategyManager_->hasAlgorithm(algorithmType_)) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario: strategy not found: " + algorithmType_);
    }
    strategy_ = strategyManager_->getStrategy(algorithmType_);
    if (!strategy_ || strategy_->kind() != Core::StrategyKind::Dynamic) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario requires a dynamic audit strategy");
    }

    engine_ = Core::AuditEngineFactory::createInstance();
    baseContext_ = Core::AuditOperationContext{};
    baseContext_.strategy = strategy_;
    fileId_ = "maintenance-" + algorithmType_;
    localIteration_ = 0;
    setupTimings_ = StageTimings{};
    lastTimings_ = StageTimings{};
    lastSucceeded_ = false;

    measure(setupTimings_.initAlgorithm, [&] {
        engine_->initializeAlgorithm(Messages::RawInput{}, baseContext_);
    });

    Json::Value keyInput;
    keyInput["userId"] = "maintenance@" + algorithmType_;
    measure(setupTimings_.generateKeys, [&] {
        engine_->generateKeys(jsonInput(keyInput), baseContext_);
    });

    stateStore_ = engine_->createStateStore(strategy_);
    if (!stateStore_) {
        throw std::runtime_error(
            "DynamicMaintenanceScenario: strategy returned a null StateStore");
    }
    stateStore_->addFile(fileId_, config_.initialBlocks);
    baseContext_.stateStore = stateStore_;
}

void DynamicMaintenanceScenario::prepare(const BenchmarkConfig&)
{}

bool DynamicMaintenanceScenario::runIteration()
{
    lastTimings_ = StageTimings{};
    Json::Value request;
    request["fileId"] = fileId_;

    // One maintenance call per iteration on a legal 1-based block index of
    // this worker's own store (each worker has its own StateStore, so indices
    // never refer to another worker's data):
    //   Update — round-robin over the initial blocks: 1..initialBlocks;
    //   Insert — append at the current block count + 1 (never shifts others);
    //   Delete — drop the current last block, consuming the store tail-first.
    Messages::MaintenanceOpType operation = Messages::MaintenanceOpType::Other;
    Json::UInt64 blockIndex = 1;
    switch (config_.operation) {
        case MaintenanceOperation::Update:
            operation = Messages::MaintenanceOpType::Update;
            blockIndex = static_cast<Json::UInt64>(
                localIteration_ % config_.initialBlocks + 1);
            break;
        case MaintenanceOperation::Insert:
            operation = Messages::MaintenanceOpType::Insert;
            blockIndex = static_cast<Json::UInt64>(
                stateStore_->getBlockCount(fileId_) + 1);
            break;
        case MaintenanceOperation::Delete:
            operation = Messages::MaintenanceOpType::Delete;
            blockIndex = static_cast<Json::UInt64>(
                stateStore_->getBlockCount(fileId_));
            break;
        default:
            throw std::invalid_argument(
                "DynamicMaintenanceScenario: unsupported operation");
    }
    request["opType"] = static_cast<unsigned>(operation);
    request["blockIndices"] = Json::Value(Json::arrayValue);
    request["blockIndices"].append(blockIndex);

    // The worker-local context is reused across iterations: it already carries
    // this worker's strategy, StateStore and setup results, and the engine
    // overwrites currentOp/maintainResult on every call.
    try {
        measure(lastTimings_.maintain, [&] {
            engine_->maintain(jsonInput(request), baseContext_);
        });
        lastSucceeded_ = true;
    } catch (const std::exception& error) {
        spdlog::warn("Maintenance benchmark operation failed: {}", error.what());
        lastSucceeded_ = false;
    } catch (...) {
        spdlog::warn("Maintenance benchmark operation failed with an unknown error");
        lastSucceeded_ = false;
    }
    ++localIteration_;
    return lastSucceeded_;
}

void DynamicMaintenanceScenario::recordIteration(MetricsCollector& collector)
{
    collector.recordMaintenanceOutcome(lastSucceeded_);
    // Ground truth for the worker's store size after the operation just
    // executed: the collector keeps the latest count, so the value left when
    // the worker's loop ends is its final size, and the runner's merge sums
    // the per-worker sizes into the run total. A rejected call leaves the
    // count unchanged, which is exactly what the result identity expects.
    if (stateStore_) {
        collector.recordWorkerFinalBlockCount(stateStore_->getBlockCount(fileId_));
    }
}

std::unique_ptr<BenchmarkResult> DynamicMaintenanceScenario::computeResult(
    const MetricsCollector& collector, const BenchmarkConfig& config)
{
    const auto* maintenanceConfig =
        dynamic_cast<const DynamicMaintenanceConfig*>(&config);
    if (!maintenanceConfig) {
        throw std::invalid_argument(
            "DynamicMaintenanceScenario requires a DynamicMaintenanceConfig");
    }
    auto result = std::make_unique<DynamicMaintenanceResult>();
    collector.fillDynamicMaintenanceResult(*result, *maintenanceConfig);
    return result;
}

StageTimings DynamicMaintenanceScenario::getSetupTimings() const
{
    return setupTimings_;
}

MessageSizes DynamicMaintenanceScenario::getSetupMessageSizes() const
{
    return {};
}

StageTimings DynamicMaintenanceScenario::getLastTimings() const
{
    return lastTimings_;
}

MessageSizes DynamicMaintenanceScenario::getLastMessageSizes() const
{
    return {};
}

void DynamicMaintenanceScenario::teardown()
{
    baseContext_ = Core::AuditOperationContext{};
    stateStore_.reset();
    engine_.reset();
    strategy_.reset();
    fileId_.clear();
    localIteration_ = 0;
    lastSucceeded_ = false;
}

} // namespace CAMatrix::Audit::Benchmark
