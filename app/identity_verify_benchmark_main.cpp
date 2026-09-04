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
 * @file identity_verify_benchmark_main.cpp
 * @brief Main entry point for the identity verification benchmark
 * @details Creates an IdentityVerifyScenario with the specified algorithm type
 *          and runs the benchmark via a factory-created ComputationStrategy
 *          (selected by --computation, default: IdentityVerify). The strategy
 *          owns CLI parsing, sweep expansion, execution, and report generation
 *          — main holds a single base-class pointer and dispatches
 *          polymorphically. The BenchmarkRunner owns a scenario factory and
 *          creates one independent IdentityVerifyScenario per parallel worker
 *          per run (each worker scenario retains its own std::random_device
 *          seeded RNG and generates its own Online session strings).
 *
 *          CLI parameters (global):
 *          --algorithm <type>          Algorithm type (default: SM9Noncert)
 *          --strategy-path <dir>       Identity algorithm library directory
 *          --computation <type>        Computation strategy (default: IdentityVerify)
 *          --iterations <N>            Iterations per combo (default: 10)
 *          --threads <N>               Parallel worker threads (default: 1; 0 = auto)
 *          --json <path>               Write JSON report to file
 *          --list-algorithms           List identity algorithms and exit
 *          --help                      Show help message
 *          (Identity sweep parameters are parsed by IdentityVerifyStrategy.)
 * @author Dylan Liu
 * @version 4.2.0
 * @date 2026-09-05
 */

#include <ChordAuditMatrixBench/benchmark_computation_strategy.h>
#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/identity_verify_scenario.h>

#include "ChordAuditMatrixLib/implementations/identity/in_memory_identity_algorithm_manager.h"
#include "ChordAuditMatrixLib/implementations/base/loader/algorithm_hot_load_decorator.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

using namespace CAMatrix::Audit::Benchmark;

/**
 * @brief Print usage information
 */
static void printUsage(const char* progName)
{
    spdlog::info("Usage: {} [options]", progName);
    spdlog::info("");
    spdlog::info("Identity Verification Benchmark — measures true/false positive/negative");
    spdlog::info("rates for identity signature verification across user scaling.");
    spdlog::info("");
    spdlog::info("Options:");
    spdlog::info("  --algorithm <type>          Algorithm type (default: SM9Noncert)");
    spdlog::info("  --strategy-path <dir>       Identity algorithm library directory");
    spdlog::info("                              (default: <exe_dir>/identity_algorithms)");
    spdlog::info("  --computation <type>        Computation strategy (default: IdentityVerify)");
    spdlog::info("  --iterations <N>            Iterations per combo (default: 10)");
    spdlog::info("  --threads <N>               Parallel worker threads (default: 1; 0 = auto: hardware_concurrency)");
    spdlog::info("  --num-users <N>             Number of users (default: 10)");
    spdlog::info("  --samples-per-iter <N>      Samples per iteration (default: 20)");
    spdlog::info("  --forgery-ratio <r>         Forgery ratio (default: 0)");
    spdlog::info("  --tampered-ratio <r>        Tampered ratio (default: 0.5)");
    spdlog::info("  --impersonation-ratio <r>   Impersonation ratio (default: 0)");
    spdlog::info("  --sweep                     Scan user counts (default list: 1,5,10,50,100,500,1000)");
    spdlog::info("  --user-values <csv>         Explicit user list");
    spdlog::info("  --user-start/--user-end/--user-step  Linear user sweep");
    spdlog::info("  --user-start/--user-end/--user-ratio Geometric user sweep");
    spdlog::info("  --json <path>               Write JSON report to file");
    spdlog::info("  --list-algorithms           List identity algorithms and exit");
    spdlog::info("  --help                      Show this help message");
    spdlog::info("");
    spdlog::info("Online algorithms (kind=Online, e.g. SM9Online): session strings are");
    spdlog::info("generated internally per sample from a canonical UUID-v4-like 36-character");
    spdlog::info("session ID and the \"IdentityVerify\" context.");
    spdlog::info("With --num-users >= 2 the aggregate scenario is enabled AUTOMATICALLY");
    spdlog::info("(n = --num-users signers per aggregate sample) — no extra flags needed.");
    spdlog::info("");
    spdlog::info("Examples:");
    spdlog::info("  {} --algorithm SM9Noncert --num-users 10 --samples-per-iter 20", progName);
    spdlog::info("  {} --algorithm SM9Noncert --sweep --user-start 1 --user-end 1024 --user-ratio 2", progName);
}

/**
 * @brief List all registered identity algorithms
 */
static void listAlgorithms(
    const std::shared_ptr<CAMatrix::Identity::Loader::InMemoryIdentityAlgorithmManager>& identityManager)
{
    auto allTypes = identityManager->listAlgorithmTypes();
    spdlog::info("Available identity algorithms ({} total):", allTypes.size());
    spdlog::info("");
    if (allTypes.empty()) {
        spdlog::info("  (none)");
        return;
    }
    for (const auto& type : allTypes) {
        auto algo = identityManager->getIdentityAlgorithm(type);
        if (algo) {
            spdlog::info("  {} (v{})", type, algo->version());
        } else {
            spdlog::info("  {} (version unknown)", type);
        }
    }
}

int main(int argc, char* argv[])
{
    // ── Pre-scan global args ──
    std::string algorithmType;  // empty → auto-select after load
    namespace fs = std::filesystem;
    std::string defaultStrategyPath =
        (fs::path(argv[0]).parent_path() / "identity_algorithms").string();
    std::string strategyPath = defaultStrategyPath;
    std::string computationType = "IdentityVerify";
    std::string jsonPath;
    bool listAlgorithmsMode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algorithm" && i + 1 < argc) {
            algorithmType = argv[++i];
        } else if (arg == "--strategy-path" && i + 1 < argc) {
            strategyPath = argv[++i];
        } else if (arg == "--computation" && i + 1 < argc) {
            computationType = argv[++i];
        } else if (arg == "--json" && i + 1 < argc) {
            jsonPath = argv[++i];
        } else if (arg == "--list-algorithms") {
            listAlgorithmsMode = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }

    // ── Create IdentityAlgorithmManager and hot-load algorithms ──
    auto identityManager = std::make_shared<
        CAMatrix::Identity::Loader::InMemoryIdentityAlgorithmManager>();
    {
        fs::path algoDir(strategyPath);
        std::error_code ec;
        fs::create_directories(algoDir, ec);
        if (ec) {
            spdlog::warn("Failed to create identity algorithm directory '{}': {}",
                         strategyPath, ec.message());
        }
        auto hotLoadDecorator = std::make_shared<
            CAMatrix::Base::Loader::AlgorithmHotLoadDecorator>(
                identityManager, "create_identity_algorithm", "destroy_identity_algorithm");
        hotLoadDecorator->loadDirectory(algoDir);
        hotLoadDecorator->setWatchDirectory(algoDir);
        hotLoadDecorator->startWatching();
        spdlog::info("AlgorithmHotLoadDecorator started watching '{}' for identity algorithm plugins",
                     strategyPath);
    }

    if (listAlgorithmsMode) {
        listAlgorithms(identityManager);
        return 0;
    }

    // ── Auto-select algorithm if not specified ──
    if (algorithmType.empty()) {
        auto available = identityManager->listAlgorithmTypes();
        if (available.empty()) {
            spdlog::error("No identity algorithm plugins loaded from '{}'. "
                         "Use --strategy-path <dir> or --list-algorithms.", strategyPath);
            return 1;
        }
        if (available.size() == 1) {
            algorithmType = available[0];
            spdlog::info("No --algorithm given; auto-selected '{}'.", algorithmType);
        } else {
            std::string availableStr;
            for (std::size_t i = 0; i < available.size(); ++i) {
                if (i > 0) availableStr += ", ";
                availableStr += available[i];
            }
            spdlog::error("Multiple identity algorithms loaded [{}]. "
                         "Specify one with --algorithm <type>.", availableStr);
            return 1;
        }
    } else if (!identityManager->hasAlgorithm(algorithmType)) {
        auto available = identityManager->listAlgorithmTypes();
        std::string availableStr;
        for (std::size_t i = 0; i < available.size(); ++i) {
            if (i > 0) availableStr += ", ";
            availableStr += available[i];
        }
        spdlog::error("Algorithm '{}' not found. Available: [{}]",
                     algorithmType, availableStr);
        return 1;
    }

    // ── Create the benchmark runner with an identity scenario factory ──
    // One independent scenario is created per worker per run by the runner;
    // each worker scenario owns its RNG and generates its own Online sessions.
    BenchmarkRunner runner(BenchmarkScenarioFactory([algorithmType, identityManager]() {
        return std::make_unique<IdentityVerifyScenario>(algorithmType, identityManager);
    }));

    // ── Factory-create the computation strategy ──
    auto strategy = createComputationStrategy(computationType);
    if (!strategy) {
        spdlog::error("Unknown computation type: '{}'. Valid: IdentityVerify (and future identity strategies)",
                     computationType);
        return 1;
    }

    // ── parseAndExpand (virtual): parse CLI args + expand into IdentityConfig list ──
    auto configs = strategy->parseAndExpand(argc, argv);
    if (configs.empty()) {
        spdlog::error("No parameter combinations produced. Check user axis ranges/generators.");
        return 1;
    }

    spdlog::info("\n=== Identity Verification Benchmark : {} ({}) ===", algorithmType, strategy->type());
    spdlog::info("Parameter combinations: {}", configs.size());

    std::vector<std::unique_ptr<BenchmarkResult>> results;
    results.reserve(configs.size());
    for (const auto& cfg : configs) {
        results.push_back(strategy->run(runner, *cfg));
    }
    spdlog::info("\n=== Benchmark Complete ===");

    auto report = strategy->createReport(results, algorithmType);
    std::cout << report->toConsole();

    if (!jsonPath.empty()) {
        std::ofstream ofs(jsonPath);
        if (ofs.is_open()) {
            ofs << report->toJson();
            ofs.close();
            spdlog::info("JSON report written to: {}", jsonPath);
        } else {
            spdlog::error("Cannot open file for writing: {}", jsonPath);
            return 1;
        }
    }

    return 0;
}
