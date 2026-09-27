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
 * @file dynamic_maintenance_benchmark_main.cpp
 * @brief CLI entry point for the dynamic PDP maintenance benchmark
 * @details Loads the strategy plugin directory through the hot-load decorator,
 *          resolves a dynamic strategy and drives DynamicMaintenanceScenario
 *          through BenchmarkRunner (one scenario per worker, iterations
 *          partitioned across threads). Prints a console report and optionally
 *          writes the JSON report. Exit codes: 0 = all operations succeeded,
 *          1 = invalid input / load or run failure, 2 = run completed with
 *          rejected maintenance operations.
 *
 *          This executable is separate from the PDP audit benchmark: PDP
 *          iterations stay audit-only (challenge → proof → verify) and never
 *          perform maintenance.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 */

#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/dynamic_maintenance_report.h>
#include <ChordAuditMatrixBench/dynamic_maintenance_scenario.h>

#include <ChordAuditMatrixLib/implementations/audit/in_memory_audit_strategy_manager.h>
#include <ChordAuditMatrixLib/implementations/base/loader/algorithm_hot_load_decorator.h>
#include <ChordAuditMatrixLib/interfaces/audit/strategy.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>

using namespace CAMatrix::Audit::Benchmark;
using InMemoryAuditStrategyManager =
    CAMatrix::Audit::Loader::InMemoryAuditStrategyManager;

namespace {

std::size_t parseSize(const char* text, const char* option)
{
    if (text == nullptr || *text == '\0' || *text == '-') {
        throw std::invalid_argument(std::string("Invalid value for ") + option);
    }
    std::size_t consumed = 0;
    const auto value = std::stoull(text, &consumed);
    if (text[consumed] != '\0' || value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string("Invalid value for ") + option);
    }
    return static_cast<std::size_t>(value);
}

void printHelp(const char* executable)
{
    std::cout
        << "Usage: " << executable << " [options]\n"
        << "Dynamic PDP maintenance benchmark: one Update/Insert/Delete call\n"
        << "per iteration against a worker-local StateStore of a dynamic strategy.\n"
        << "\n"
        << "Options:\n"
        << "  --algorithm <type>        Dynamic strategy type (default: DHTDynamic)\n"
        << "  --strategy-path <dir>     Strategy plugin directory (default: ./strategies)\n"
        << "  --operation <type>        update | insert | delete (default: update)\n"
        << "  --initial-blocks <N>      Blocks pre-filled in each worker's StateStore\n"
        << "                            (default: 1000; delete needs N >= the largest\n"
        << "                            worker's iteration share)\n"
        << "  --iterations <N>          Total maintenance calls across all workers\n"
        << "                            (default: 100)\n"
        << "  --threads <N>             Worker count (0 = hardware concurrency)\n"
        << "  --seed <N>                Seed the benchmark PRNG (index selection is\n"
        << "                            deterministic; accepted for CLI parity)\n"
        << "  --json <path>             Write the JSON result to this file\n"
        << "  --help                    Show this help\n"
        << "\n"
        << "Exit codes: 0 = all operations succeeded, 1 = invalid input or run\n"
        << "failure, 2 = run completed with rejected operations.\n";
}

} // namespace

int main(int argc, char* argv[])
{
    namespace fs = std::filesystem;
    std::string algorithmType = "DHTDynamic";
    std::string strategyPath =
        (fs::path(argv[0]).parent_path() / "strategies").string();
    std::string jsonPath;
    DynamicMaintenanceConfig config;

    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            auto value = [&](const char* option) -> const char* {
                if (i + 1 >= argc) {
                    throw std::invalid_argument(std::string("Missing value for ") + option);
                }
                return argv[++i];
            };
            if (arg == "--help") {
                printHelp(argv[0]);
                return 0;
            } else if (arg == "--algorithm") {
                algorithmType = value("--algorithm");
            } else if (arg == "--strategy-path") {
                strategyPath = value("--strategy-path");
            } else if (arg == "--operation") {
                const std::string operation = value("--operation");
                if (operation == "update") {
                    config.operation = MaintenanceOperation::Update;
                } else if (operation == "insert") {
                    config.operation = MaintenanceOperation::Insert;
                } else if (operation == "delete") {
                    config.operation = MaintenanceOperation::Delete;
                } else {
                    throw std::invalid_argument(
                        "--operation must be update, insert, or delete");
                }
            } else if (arg == "--initial-blocks") {
                config.initialBlocks = parseSize(value("--initial-blocks"), "--initial-blocks");
            } else if (arg == "--iterations") {
                config.iterations = parseSize(value("--iterations"), "--iterations");
            } else if (arg == "--threads") {
                config.threads = parseSize(value("--threads"), "--threads");
            } else if (arg == "--seed") {
                config.seed = parseSize(value("--seed"), "--seed");
                config.usePseudoRandom = true;
            } else if (arg == "--json") {
                jsonPath = value("--json");
            } else {
                throw std::invalid_argument("Unknown option: " + arg);
            }
        }

        if (config.iterations == 0) {
            throw std::invalid_argument("--iterations must be greater than zero");
        }
        if (config.initialBlocks == 0) {
            throw std::invalid_argument("--initial-blocks must be greater than zero");
        }

        auto strategyManager = std::make_shared<InMemoryAuditStrategyManager>();
        std::error_code ec;
        fs::create_directories(strategyPath, ec);
        if (ec) {
            throw std::runtime_error(
                "Cannot create strategy directory: " + ec.message());
        }
        auto hotLoader = std::make_shared<
            CAMatrix::Base::Loader::AlgorithmHotLoadDecorator>(
                strategyManager, "create_audit_strategy", "destroy_audit_strategy");
        hotLoader->loadDirectory(strategyPath);
        hotLoader->setWatchDirectory(strategyPath);
        hotLoader->startWatching();

        if (!strategyManager->hasAlgorithm(algorithmType)) {
            throw std::invalid_argument(
                "Dynamic strategy not found: " + algorithmType);
        }
        const auto strategy = strategyManager->getStrategy(algorithmType);
        if (!strategy || strategy->kind() != CAMatrix::Audit::Core::StrategyKind::Dynamic) {
            throw std::invalid_argument(
                "Dynamic maintenance benchmark requires a dynamic strategy");
        }

        BenchmarkRunner runner(BenchmarkScenarioFactory(
            [algorithmType, strategyManager] {
                return std::make_unique<DynamicMaintenanceScenario>(
                    algorithmType, strategyManager);
            }));
        auto baseResult = runner.runSingle(config);
        auto* result = dynamic_cast<DynamicMaintenanceResult*>(baseResult.get());
        if (!result) {
            throw std::runtime_error("Maintenance runner returned an unexpected result type");
        }

        std::cout << dynamicMaintenanceConsoleReport(*result);
        if (!jsonPath.empty()) {
            std::ofstream output(jsonPath);
            if (!output) {
                throw std::runtime_error("Cannot open JSON output: " + jsonPath);
            }
            output << dynamicMaintenanceJsonReport(*result);
        }
        hotLoader->stopWatching();
        if (result->failedOperations > 0) {
            spdlog::error("{} maintenance operation(s) were rejected — see the report above",
                          result->failedOperations);
            return 2;
        }
        return 0;
    } catch (const std::exception& error) {
        spdlog::error("{}", error.what());
        return 1;
    }
}
