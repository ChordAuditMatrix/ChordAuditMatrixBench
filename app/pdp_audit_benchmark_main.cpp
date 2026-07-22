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
 * @file pdp_audit_benchmark_main.cpp
 * @brief Main entry point for the PDP audit benchmark
 * @details Creates an InMemoryAuditStrategyManager, hot-loads audit strategy
 *          plugins from a directory, then constructs a PdpAuditScenario and runs
 *          the benchmark via a ComputationStrategy (factory-created from
 *          --computation). The strategy owns CLI argument parsing, sweep
 *          expansion, execution, and report generation — main holds a single
 *          base-class pointer and dispatches polymorphically.
 *
 *          CLI parameters (algorithm/plugin/global):
 *          --algorithm <type>            Algorithm type (default: SM9Static)
 *          --strategy-path <dir>         Strategy library directory
 *          --computation <type>          PdpDirect / PdpFixedRatio / PdpInverseConfidence
 *          --iterations <N>              Iterations per combo (default: 10)
 *          --maintenance-ops <N>         Dynamic PDP maintenance ops (default: 0)
 *          --json <path>                 Write JSON report to file
 *          --list-algorithms             List all available algorithms and exit
 *          --help                        Show help message
 *          (Computation-specific sweep parameters are documented in --help.)
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
 */

#include <ChordAuditMatrixBench/benchmark_computation_strategy.h>
#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/pdp_audit_scenario.h>

#include "ChordAuditMatrixLib/implementations/audit/in_memory_audit_strategy_manager.h"
#include "ChordAuditMatrixLib/implementations/base/loader/algorithm_hot_load_decorator.h"
#include "ChordAuditMatrixLib/interfaces/audit/strategy.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

using namespace CAMatrix::Audit::Benchmark;
using InMemoryAuditStrategyManager = CAMatrix::Audit::Loader::InMemoryAuditStrategyManager;

/**
 * @brief Print usage information
 */
static void printUsage(const char* progName)
{
    spdlog::info("Usage: {} [options]", progName);
    spdlog::info("");
    spdlog::info("PDP Audit Benchmark — measures detection confidence vs theoretical");
    spdlog::info("hypergeometric probability for static and dynamic PDP schemes.");
    spdlog::info("");
    spdlog::info("Options:");
    spdlog::info("  --algorithm <type>          Algorithm type (default: SM9Static)");
    spdlog::info("                             SM9Static  — certificateless static PDP");
    spdlog::info("                             DHTDynamic — dynamic PDP with DHT state store");
    spdlog::info("  --strategy-path <dir>       Strategy library directory for hot-loading");
    spdlog::info("  --computation <type>        Computation strategy (default: PdpDirect)");
    spdlog::info("                             PdpDirect            — explicit (N,t,r) or t/r sweeps at fixed N");
    spdlog::info("                             PdpFixedRatio        — fixed t/N, r/N ratios, scan N");
    spdlog::info("                             PdpInverseConfidence — target P*, scan N, solve min r");
    spdlog::info("  --iterations <N>            Iterations per combo (default: 10)");
    spdlog::info("  --maintenance-ops <N>       Maintenance ops before audit (dynamic only, default: 0)");
    spdlog::info("  --json <path>               Write JSON report to file");
    spdlog::info("  --list-algorithms           List all available algorithms and exit");
    spdlog::info("  --help                      Show this help message");
    spdlog::info("");
    spdlog::info("Computation-specific parameters (parsed by the chosen strategy):");
    spdlog::info("  PdpDirect: --total-blocks --corrupted-blocks --sample-size");
    spdlog::info("             --t-values/--t-start/--t-end/--t-step/--t-ratio");
    spdlog::info("             --r-values/--r-start/--r-end/--r-step/--r-ratio");
    spdlog::info("  PdpFixedRatio: --corrupted-ratio --sample-ratio");
    spdlog::info("                 --n-values/--n-start/--n-end/--n-step/--n-ratio");
    spdlog::info("  PdpInverseConfidence: --target-confidence --corrupted-ratio");
    spdlog::info("                        --n-values/--n-start/--n-end/--n-step/--n-ratio");
    spdlog::info("");
    spdlog::info("Examples:");
    spdlog::info("  # Single run: 1000 blocks, 10 corrupted, sample 50, 10 iterations");
    spdlog::info("  {} --algorithm DHTDynamic --total-blocks 1000 \\", progName);
    spdlog::info("      --corrupted-blocks 10 --sample-size 50 --iterations 10");
    spdlog::info("");
    spdlog::info("  # Sweep fixed N, scan (t, r)");
    spdlog::info("  {} --algorithm DHTDynamic --computation PdpDirect \\", progName);
    spdlog::info("      --total-blocks 1000 --t-values 1,5,10,50,100 --r-values 10,50,100,200");
    spdlog::info("");
    spdlog::info("  # Fixed ratios, scan N geometric");
    spdlog::info("  {} --algorithm SM9Static --computation PdpFixedRatio \\", progName);
    spdlog::info("      --corrupted-ratio 0.01 --sample-ratio 0.05 --n-start 100 --n-end 10240 --n-ratio 2");
    spdlog::info("");
    spdlog::info("  # Inverse confidence: target P*=0.96, corruption 2%, scan N");
    spdlog::info("  {} --algorithm SM9Static --computation PdpInverseConfidence \\", progName);
    spdlog::info("      --target-confidence 0.96 --corrupted-ratio 0.02 --n-start 100 --n-end 10000 --n-ratio 2");
}

/**
 * @brief List all registered algorithms grouped by strategy kind (Static / Dynamic)
 */
static void listAlgorithms(
    const std::shared_ptr<InMemoryAuditStrategyManager>& strategyManager)
{
    auto allTypes = strategyManager->listAlgorithmTypes();

    std::vector<std::pair<std::string, std::string>> staticAlgos;
    std::vector<std::pair<std::string, std::string>> dynamicAlgos;

    for (const auto& type : allTypes) {
        auto strategy = strategyManager->getStrategy(type);
        if (!strategy) continue;
        auto version = strategy->version();
        if (strategy->kind() == CAMatrix::Audit::Core::StrategyKind::Dynamic) {
            dynamicAlgos.emplace_back(type, version);
        } else {
            staticAlgos.emplace_back(type, version);
        }
    }

    spdlog::info("Available algorithms ({} total):", allTypes.size());
    spdlog::info("");

    spdlog::info("  Static PDP (no dynamic maintenance):");
    if (staticAlgos.empty()) {
        spdlog::info("    (none)");
    } else {
        for (const auto& a : staticAlgos) {
            spdlog::info("    {} (v{})", a.first, a.second);
        }
    }
    spdlog::info("");

    spdlog::info("  Dynamic PDP (supports Insert/Update/Delete maintenance):");
    if (dynamicAlgos.empty()) {
        spdlog::info("    (none)");
    } else {
        for (const auto& a : dynamicAlgos) {
            spdlog::info("    {} (v{})", a.first, a.second);
        }
    }
}

int main(int argc, char* argv[])
{
    // ── Pre-scan global args: algorithm / strategy-path / json / list / help / computation ──
    std::string algorithmType = "SM9Static";
    namespace fs = std::filesystem;
    std::string defaultStrategyPath =
        (fs::path(argv[0]).parent_path() / "strategies").string();
    std::string strategyPath = defaultStrategyPath;
    std::string jsonPath;
    bool listAlgorithmsMode = false;
    std::string computationType = "PdpDirect";

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

    // ── Create InMemoryAuditStrategyManager ──
    auto strategyManager = std::make_shared<InMemoryAuditStrategyManager>();
    {
        fs::path strategyDir(strategyPath);
        std::error_code ec;
        fs::create_directories(strategyDir, ec);
        if (ec) {
            spdlog::warn("Failed to create strategy directory '{}': {}",
                         strategyPath, ec.message());
        }
        auto hotLoadDecorator = std::make_shared<
            CAMatrix::Base::Loader::AlgorithmHotLoadDecorator>(
                strategyManager, "create_audit_strategy", "destroy_audit_strategy");
        hotLoadDecorator->loadDirectory(strategyDir);
        hotLoadDecorator->setWatchDirectory(strategyDir);
        hotLoadDecorator->startWatching();
        spdlog::info("AlgorithmHotLoadDecorator started watching '{}' for audit strategy plugins",
                     strategyPath);
    }

    if (listAlgorithmsMode) {
        listAlgorithms(strategyManager);
        return 0;
    }

    if (!strategyManager->hasAlgorithm(algorithmType)) {
        auto available = strategyManager->listAlgorithmTypes();
        std::string availableStr;
        for (std::size_t i = 0; i < available.size(); ++i) {
            if (i > 0) availableStr += ", ";
            availableStr += available[i];
        }
        spdlog::error("Algorithm '{}' not found. Available: [{}]",
                     algorithmType, availableStr);
        return 1;
    }

    // ── Create PDP audit scenario + runner ──
    auto scenario = std::make_unique<PdpAuditScenario>(algorithmType, strategyManager);
    BenchmarkRunner runner(std::move(scenario));

    // ── Factory-create the computation strategy ──
    auto strategy = createComputationStrategy(computationType);
    if (!strategy) {
        spdlog::error("Unknown computation type: '{}'. Valid: PdpDirect / PdpFixedRatio / PdpInverseConfidence",
                     computationType);
        return 1;
    }

    // ── parseAndExpand: parse CLI args + expand into typed configs (all virtual) ──
    auto configs = strategy->parseAndExpand(argc, argv);
    if (configs.empty()) {
        spdlog::error("No parameter combinations produced. Check axis ranges/generators.");
        return 1;
    }

    spdlog::info("\n=== PDP Audit Benchmark : {} ({}) ===", algorithmType, strategy->type());
    spdlog::info("Parameter combinations: {}", configs.size());

    // ── Run each config (virtual run) ──
    std::vector<std::unique_ptr<BenchmarkResult>> results;
    results.reserve(configs.size());
    for (const auto& cfg : configs) {
        results.push_back(strategy->run(runner, *cfg));
    }
    spdlog::info("\n=== Benchmark Complete ===");

    // ── Build report (virtual createReport) ──
    auto report = strategy->createReport(results, runner.algorithmType());
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
