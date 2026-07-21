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
 *          and runs the benchmark via BenchmarkRunner. Supports both single-run
 *          and parameter-sweep (user scaling) modes.
 *
 *          CLI parameters:
 *          --algorithm \&lt;type\&gt;        Algorithm type (default: SM9Noncert)
 *          --iterations \&lt;N\&gt;          Iterations per parameter combo (default: 10)
 *          --num-users \&lt;N\&gt;           Number of participating users (default: 10)
 *          --samples-per-iter \&lt;N\&gt;    Samples verified per iteration (default: 20)
 *          --forgery-ratio \&lt;r\&gt;       Forgery negative sample ratio (default: 0.25)
 *          --tampered-ratio \&lt;r\&gt;      Tampered message negative sample ratio (default: 0.25)
 *          --impersonation-ratio \&lt;r\&gt; Impersonation negative sample ratio (default: 0.25)
 *          --sweep                   Enable parameter sweep (scan user counts)
 *          --json \&lt;path\&gt;             Write JSON report to file
 *          --list-algorithms          List all available identity algorithms and exit
 *          --help                    Show help message
 * @author Dylan Liu
 * @version 2.1.0
 * @date 2026-07-05
 */

#include <ChordAuditMatrixBench/benchmark_config.h>
#include <ChordAuditMatrixBench/benchmark_report.h>
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

using namespace CAMatrix::Audit::Benchmark;

/**
 * @brief Parse a comma-separated list of non-negative integers
 * @param s Input string like "1,5,10,50,100"
 * @return Parsed vector; empty if input is empty or any token fails to parse
 */
static std::vector<std::size_t> parseCsvSizeT(const std::string& s)
{
    std::vector<std::size_t> out;
    if (s.empty()) return out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t j = s.find(',', i);
        std::string tok = (j == std::string::npos) ? s.substr(i) : s.substr(i, j - i);
        if (tok.empty()) return {}; // malformed: "1,,2" or trailing ","
        try {
            out.push_back(static_cast<std::size_t>(std::stoull(tok)));
        } catch (...) {
            return {}; // non-numeric token
        }
        if (j == std::string::npos) break;
        i = j + 1;
    }
    return out;
}

/**
 * @brief Print usage information
 * @param progName Program name (argv[0])
 */
static void printUsage(const char* progName)
{
    spdlog::info("Usage: {} [options]", progName);
    spdlog::info("");
    spdlog::info("Identity Verification Benchmark — measures true/false positive/negative");
    spdlog::info("rates for identity signature verification across user scaling.");
    spdlog::info("");
    spdlog::info("Options:");
    spdlog::info("  --algorithm <type>        Algorithm type (default: SM9Noncert)");
    spdlog::info("                             SM9Noncert — certificateless SM9 identity signing");
    spdlog::info("  --strategy-path <dir>     Identity algorithm library directory");
    spdlog::info("                             (default: <exe_dir>/identity_algorithms)");
    spdlog::info("  --iterations <N>          Iterations per parameter combo (default: 10)");
    spdlog::info("  --num-users <N>           Number of participating users (default: 10)");
    spdlog::info("  --samples-per-iter <N>    Samples verified per iteration (default: 20)");
    spdlog::info("  --forgery-ratio <r>       Forgery negative sample ratio (default: 0.25)");
    spdlog::info("                             Forged signature on a legitimate message");
    spdlog::info("  --tampered-ratio <r>      Tampered message negative sample ratio (default: 0.25)");
    spdlog::info("                             Legitimate signature on a tampered message");
    spdlog::info("  --impersonation-ratio <r> Impersonation negative sample ratio (default: 0.25)");
    spdlog::info("                             Legitimate signature claimed by a different user");
    spdlog::info("  --sweep                   Enable parameter sweep (scan user counts)");
    spdlog::info("                             Default list: {{1,5,10,50,100,500,1000}}");
    spdlog::info("");
    spdlog::info("  Custom user axis (override the default list):");
    spdlog::info("  --user-values <csv>       Explicit user list, e.g. --user-values 1,2,5,10,20");
    spdlog::info("  --user-start <N>          Generated users: first value");
    spdlog::info("  --user-end <N>            Generated users: inclusive upper bound");
    spdlog::info("  --user-step <N>           Linear users increment (use with --user-start/--user-end)");
    spdlog::info("  --user-ratio <r>          Geometric users multiplier (use with --user-start/--user-end)");
    spdlog::info("                             e.g. --user-start 1 --user-end 1024 --user-ratio 2");
    spdlog::info("                                 => 1,2,4,8,16,32,64,128,256,512,1024");
    spdlog::info("");
    spdlog::info("  Axis resolution rules:");
    spdlog::info("    - Exactly one source allowed: explicit list, linear, or geometric.");
    spdlog::info("      Mixing errors out.");
    spdlog::info("    - If none is given, the default hardcoded list is used.");
    spdlog::info("    - Geometric requires ratio > 1.0; otherwise it would never progress.");
    spdlog::info("");
    spdlog::info("  --json <path>             Write JSON report to file");
    spdlog::info("  --list-algorithms          List all available identity algorithms and exit");
    spdlog::info("  --help                    Show this help message");
    spdlog::info("");
    spdlog::info("Negative sample ratios must sum to <= 1.0. The remaining fraction");
    spdlog::info("is allocated to positive (legitimate) samples.");
    spdlog::info("");
    spdlog::info("Examples:");
    spdlog::info("  # Single run: 10 users, 20 samples per iteration, 10 iterations");
    spdlog::info("  {} --algorithm SM9Noncert --num-users 10 --samples-per-iter 20", progName);
    spdlog::info("");
    spdlog::info("  # Sweep: scan user counts from 1 to 1000");
    spdlog::info("  {} --algorithm SM9Noncert --sweep", progName);
    spdlog::info("");
    spdlog::info("  # Custom explicit user list");
    spdlog::info("  {} --algorithm SM9Noncert --sweep --user-values 1,3,7,15,31,63", progName);
    spdlog::info("");
    spdlog::info("  # Geometric user sweep: 1 -> 1024, ratio 2");
    spdlog::info("  {} --algorithm SM9Noncert --sweep \\", progName);
    spdlog::info("      --user-start 1 --user-end 1024 --user-ratio 2");
    spdlog::info("");
    spdlog::info("  # Linear user sweep: 10 -> 100, step 10");
    spdlog::info("  {} --algorithm SM9Noncert --sweep \\", progName);
    spdlog::info("      --user-start 10 --user-end 100 --user-step 10");
    spdlog::info("");
    spdlog::info("  # Custom negative sample ratios (50% forgery, 25% tampered, 25% impersonation)");
    spdlog::info("  {} --algorithm SM9Noncert --forgery-ratio 0.50 \\", progName);
    spdlog::info("      --tampered-ratio 0.25 --impersonation-ratio 0.25");
    spdlog::info("");
    spdlog::info("  # Single run with JSON output");
    spdlog::info("  {} --algorithm SM9Noncert --json report.json", progName);
    spdlog::info("");
    spdlog::info("  # List all available identity algorithms");
    spdlog::info("  {} --list-algorithms", progName);
}

/**
 * @brief List all registered identity algorithms with type and version
 * @param identityManager Identity algorithm manager with registered algorithms
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
    // ── Default parameters ──
    std::string algorithmType = "SM9Noncert";
    // Default strategy path: <exe_dir>/identity_algorithms (same convention as server config)
    namespace fs = std::filesystem;
    std::string defaultStrategyPath =
        (fs::path(argv[0]).parent_path() / "identity_algorithms").string();
    std::string strategyPath = defaultStrategyPath;
    std::size_t iterations = 10;
    std::size_t numUsers = 10;
    std::size_t samplesPerIteration = 20;
    double forgeryRatio = 0.25;
    double tamperedRatio = 0.25;
    double impersonationRatio = 0.25;
    bool sweepMode = false;
    std::string jsonPath;
    bool listAlgorithmsMode = false;

    // ── Custom user sweep axis inputs (empty => use default hardcoded list) ──
    std::string userValuesCsv;
    bool userStartSet = false, userEndSet = false, userStepSet = false, userRatioSet = false;
    std::size_t userStart = 0, userEnd = 0, userStep = 0;
    double userRatio = 2.0;

    // ── Parse command-line arguments ──
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algorithm" && i + 1 < argc) {
            algorithmType = argv[++i];
        } else if (arg == "--strategy-path" && i + 1 < argc) {
            strategyPath = argv[++i];
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--num-users" && i + 1 < argc) {
            numUsers = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--samples-per-iter" && i + 1 < argc) {
            samplesPerIteration = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--forgery-ratio" && i + 1 < argc) {
            forgeryRatio = std::atof(argv[++i]);
        } else if (arg == "--tampered-ratio" && i + 1 < argc) {
            tamperedRatio = std::atof(argv[++i]);
        } else if (arg == "--impersonation-ratio" && i + 1 < argc) {
            impersonationRatio = std::atof(argv[++i]);
        } else if (arg == "--sweep") {
            sweepMode = true;
        } else if (arg == "--user-values" && i + 1 < argc) {
            userValuesCsv = argv[++i];
        } else if (arg == "--user-start" && i + 1 < argc) {
            userStart = static_cast<std::size_t>(std::atol(argv[++i])); userStartSet = true;
        } else if (arg == "--user-end" && i + 1 < argc) {
            userEnd = static_cast<std::size_t>(std::atol(argv[++i])); userEndSet = true;
        } else if (arg == "--user-step" && i + 1 < argc) {
            userStep = static_cast<std::size_t>(std::atol(argv[++i])); userStepSet = true;
        } else if (arg == "--user-ratio" && i + 1 < argc) {
            userRatio = std::atof(argv[++i]); userRatioSet = true;
        } else if (arg == "--json" && i + 1 < argc) {
            jsonPath = argv[++i];
        } else if (arg == "--list-algorithms") {
            listAlgorithmsMode = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else {
            spdlog::error("Unknown option: {}", arg);
            printUsage(argv[0]);
            return 1;
        }
    }

    // ── Validate negative sample ratios ──
    double totalNegRatio = forgeryRatio + tamperedRatio + impersonationRatio;
    if (totalNegRatio > 1.0) {
        spdlog::error("Sum of negative sample ratios ({}) exceeds 1.0. Positive sample ratio would be negative.",
                     totalNegRatio);
        return 1;
    }

    // ── Create IdentityAlgorithmManager and load algorithms as plugins ──
    auto identityManager = std::make_shared<
        CAMatrix::Identity::Loader::InMemoryIdentityAlgorithmManager>();

    // ── Load all identity algorithms (built-in and external) as plugins ──
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

    // ── Validate target algorithm is available ──
    if (listAlgorithmsMode) {
        listAlgorithms(identityManager);
        return 0;
    }

    if (!identityManager->hasAlgorithm(algorithmType)) {
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

    // ── Create identity verify scenario ──
    auto scenario = std::make_unique<IdentityVerifyScenario>(algorithmType, identityManager);

    // ── Run benchmark ──
    BenchmarkRunner runner(std::move(scenario));
    std::vector<BenchmarkResult> results;

    if (sweepMode) {
        // Parameter sweep: scan user counts

        // ── Configure user axis from CLI inputs ──
        // Sources allowed (mutually exclusive):
        //   1) explicit CSV list
        //   2) linear generator (start + step)
        //   3) geometric generator (start + ratio)
        int srcCount = !userValuesCsv.empty() ? 1 : 0;
        srcCount += (userStartSet && userStepSet) ? 1 : 0;
        srcCount += (userStartSet && userRatioSet) ? 1 : 0;
        if (srcCount > 1) {
            spdlog::error("Conflicting user axis sources: provide at most one of "
                          "explicit list / linear (start+step) / geometric (start+ratio).");
            return 1;
        }
        if (userStartSet && !(userStepSet || userRatioSet)) {
            spdlog::error("--user-start given without --user-step or --user-ratio.");
            return 1;
        }
        if ((userStepSet && !userStartSet) || (userRatioSet && !userStartSet)) {
            spdlog::error("--user-step/--user-ratio given without --user-start.");
            return 1;
        }
        if (!userEndSet && (userStartSet && (userStepSet || userRatioSet))) {
            spdlog::error("--user-end is required when using a generator (linear/geometric).");
            return 1;
        }

        auto sweep = defaultIdentitySweep(iterations, samplesPerIteration);

        // Override negative sample ratios with CLI values
        sweep.negativeSamples.forgeryRatio = forgeryRatio;
        sweep.negativeSamples.tamperedRatio = tamperedRatio;
        sweep.negativeSamples.impersonationRatio = impersonationRatio;

        // Apply user axis configuration (overriding the default hardcoded list
        // from defaultIdentitySweep only when the user gave input).
        if (!userValuesCsv.empty()) {
            sweep.userValues = parseCsvSizeT(userValuesCsv);
            if (sweep.userValues.empty()) {
                spdlog::error("Failed to parse explicit user list: '{}'", userValuesCsv);
                return 1;
            }
            sweep.userSpec.gen = SweepGen::Explicit;
        } else if (userStartSet && userStepSet) {
            if (userStep == 0) {
                spdlog::error("Linear user step must be > 0.");
                return 1;
            }
            if (userEnd < userStart) {
                spdlog::error("Linear user end ({}) < start ({}).", userEnd, userStart);
                return 1;
            }
            sweep.userSpec.gen = SweepGen::Linear;
            sweep.userSpec.start = userStart;
            sweep.userSpec.end = userEnd;
            sweep.userSpec.step = userStep;
        } else if (userStartSet && userRatioSet) {
            if (userRatio <= 1.0) {
                spdlog::error("Geometric user ratio must be > 1.0 (got {}).", userRatio);
                return 1;
            }
            if (userEnd < userStart) {
                spdlog::error("Geometric user end ({}) < start ({}).", userEnd, userStart);
                return 1;
            }
            sweep.userSpec.gen = SweepGen::Geometric;
            sweep.userSpec.start = userStart;
            sweep.userSpec.end = userEnd;
            sweep.userSpec.ratio = userRatio;
        }

        // Final safety: ensure the resolved sweep produces at least one config
        auto probe = expandSweep(sweep);
        if (probe.empty()) {
            spdlog::error("Sweep produced 0 parameter combinations. Check user axis ranges/generators.");
            return 1;
        }

        results = runner.runSweep(sweep);
    } else {
        // Single-run mode
        BenchmarkConfig config;
        config.numUsers = numUsers;
        config.samplesPerIteration = samplesPerIteration;
        config.iterations = iterations;
        config.negativeSamples.forgeryRatio = forgeryRatio;
        config.negativeSamples.tamperedRatio = tamperedRatio;
        config.negativeSamples.impersonationRatio = impersonationRatio;

        results.push_back(runner.runSingle(config));
    }

    // ── Output report ──
    std::cout << BenchmarkReport::toConsole(results, algorithmType);

    if (!jsonPath.empty()) {
        std::ofstream ofs(jsonPath);
        if (ofs.is_open()) {
            ofs << BenchmarkReport::toJson(results, algorithmType);
            ofs.close();
            spdlog::info("JSON report written to: {}", jsonPath);
        } else {
            spdlog::error("Cannot open file for writing: {}", jsonPath);
            return 1;
        }
    }

    return 0;
}
