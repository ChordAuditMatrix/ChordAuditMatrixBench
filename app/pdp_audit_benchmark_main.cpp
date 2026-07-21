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
 * @details Creates an InMemoryAuditStrategyManager, registers built-in strategies
 *          (SM9Static, DHTDynamic), optionally loads external strategy libraries, then constructs a
 *          PdpAuditScenario and runs the benchmark via BenchmarkRunner.
 *          Supports both single-run and parameter-sweep modes.
 *
 *          CLI parameters:
 *          --algorithm \&lt;type\&gt;       Algorithm type (default: SM9Static)
 *          --strategy-path \&lt;dir\&gt;    Strategy library directory
 *          --iterations \&lt;N\&gt;         Iterations per parameter combo (default: 10)
 *          --total-blocks \&lt;N\&gt;       Total data blocks N (default: 1000)
 *          --corrupted-blocks \&lt;N\&gt;   Corrupted blocks t (default: 10)
 *          --sample-size \&lt;N\&gt;        Sample size r (default: 50)
 *          --stale-version-ratio \&lt;ratio\&gt;  Stale version ratio for dynamic PDP (0.0~1.0, default: 0.0)
 *          --maintenance-ops \&lt;N\&gt;        Number of maintenance ops before audit (default: 0)
 *          --sweep                  Enable parameter sweep mode
 *          --sweep-mode \&lt;mode\&gt;      Sweep mode: fixedN (default) or fixedRatio
 *          --json \&lt;path\&gt;            Write JSON report to file
 *          --list-algorithms        List all available algorithms by category and exit
 *          --help                   Show help message
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-05
 */

#include <ChordAuditMatrixBench/benchmark_config.h>
#include <ChordAuditMatrixBench/benchmark_report.h>
#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/pdp_audit_scenario.h>

#include "ChordAuditMatrixLib/implementations/audit/in_memory_audit_strategy_manager.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_hash_table_state_store.h"
#include "ChordAuditMatrixLib/implementations/base/loader/algorithm_hot_load_decorator.h"
#include "ChordAuditMatrixLib/interfaces/audit/strategy.h"

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>

using namespace CAMatrix::Audit::Benchmark;
using InMemoryAuditStrategyManager = CAMatrix::Audit::Loader::InMemoryAuditStrategyManager;

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
    spdlog::info("PDP Audit Benchmark — measures detection confidence vs theoretical");
    spdlog::info("hypergeometric probability for static and dynamic PDP schemes.");
    spdlog::info("");
    spdlog::info("Options:");
    spdlog::info("  --algorithm <type>          Algorithm type (default: SM9Static)");
    spdlog::info("                             SM9Static  — certificateless static PDP");
    spdlog::info("                             DHTDynamic — dynamic PDP with DHT state store");
    spdlog::info("  --strategy-path <dir>       Strategy library directory for hot-loading");
    spdlog::info("                             (default: <exe_dir>/strategies)");
    spdlog::info("  --iterations <N>            Iterations per parameter combo (default: 10)");
    spdlog::info("  --total-blocks <N>         Total data blocks N (default: 1000)");
    spdlog::info("  --corrupted-blocks <N>     Corrupted/stale blocks t (default: 10)");
    spdlog::info("                             Static: blocks whose data is bit-flipped");
    spdlog::info("                             Dynamic: blocks whose version is bumped");
    spdlog::info("  --sample-size <N>          Sample size r per audit (default: 50)");
    spdlog::info("  --corrupted-ratio <r>      Corrupted blocks as ratio of total (alternative to --corrupted-blocks)");
    spdlog::info("  --sample-ratio <r>         Sample size as ratio of total (alternative to --sample-size)");
    spdlog::info("  --maintenance-ops <N>      Maintenance ops before audit (default: 0)");
    spdlog::info("                             Dynamic only: Insert/Update/Delete before audit");
    spdlog::info("  --sweep                     Enable parameter sweep mode");
    spdlog::info("  --sweep-mode <mode>         Sweep mode (default: fixedN)");
    spdlog::info("                             fixedN      — fixed N, sweep (t, r) combos");
    spdlog::info("                                          t in {{1,5,10,50,100}}, r in {{10,50,100,200}}");
    spdlog::info("                             fixedRatio  — fixed t/N and r/N ratios, sweep N");
    spdlog::info("                                          N in {{100,500,1000,5000,10000}}");
    spdlog::info("");
    spdlog::info("  Custom sweep axes (override the default hardcoded lists):");
    spdlog::info("  --t-values <csv>            Explicit t list, e.g. --t-values 1,2,5,10,20");
    spdlog::info("  --t-start <N>               Generated t: first value");
    spdlog::info("  --t-end <N>                 Generated t: inclusive upper bound");
    spdlog::info("  --t-step <N>                Linear t: increment (use with --t-start/--t-end)");
    spdlog::info("  --t-ratio <r>               Geometric t: multiplier (use with --t-start/--t-end)");
    spdlog::info("  --r-values <csv>            Explicit r list, e.g. --r-values 10,50,100,200");
    spdlog::info("  --r-start <N> --r-end <N>   Generated r range (with --r-step or --r-ratio)");
    spdlog::info("  --r-step <N>                Linear r increment");
    spdlog::info("  --r-ratio <r>               Geometric r multiplier");
    spdlog::info("  --n-values <csv>            Explicit N list (fixedRatio mode)");
    spdlog::info("  --n-start <N> --n-end <N>  Generated N range (with --n-step or --n-ratio)");
    spdlog::info("  --n-step <N>                Linear N increment");
    spdlog::info("  --n-ratio <r>               Geometric N multiplier (e.g. 2 => 100,200,400,...)");
    spdlog::info("");
    spdlog::info("  Axis resolution rules:");
    spdlog::info("    - For each axis, exactly one source is allowed: explicit list,");
    spdlog::info("      linear (start+step), or geometric (start*ratio). Mixing errors out.");
    spdlog::info("    - If none is given, the default hardcoded list is used (see --sweep-mode).");
    spdlog::info("    - Geometric requires ratio > 1.0; otherwise it would never progress.");
    spdlog::info("");
    spdlog::info("  --json <path>               Write JSON report to file");
    spdlog::info("  --list-algorithms           List all available algorithms by category and exit");
    spdlog::info("  --help                      Show this help message");
    spdlog::info("");
    spdlog::info("Examples:");
    spdlog::info("  # Single run: 1000 blocks, 10 corrupted, sample 50, 10 iterations");
    spdlog::info("  {} --algorithm DHTDynamic --total-blocks 1000 --corrupted-blocks 10 \\", progName);
    spdlog::info("      --sample-size 50 --iterations 10");
    spdlog::info("");
    spdlog::info("  # Sweep: fixed N=1000, sweep (t, r) combinations");
    spdlog::info("  {} --algorithm DHTDynamic --sweep --sweep-mode fixedN", progName);
    spdlog::info("");
    spdlog::info("  # Sweep: fixed ratios (t/N=1%, r/N=5%), scan N from 100 to 10000");
    spdlog::info("  {} --algorithm SM9Static --sweep --sweep-mode fixedRatio \\", progName);
    spdlog::info("      --total-blocks 1000 --corrupted-blocks 10 --sample-size 50");
    spdlog::info("");
    spdlog::info("  # Custom explicit t/r lists (fixedN mode)");
    spdlog::info("  {} --algorithm DHTDynamic --sweep --sweep-mode fixedN \\", progName);
    spdlog::info("      --t-values 1,2,4,8,16 --r-values 50,100,200");
    spdlog::info("");
    spdlog::info("  # Geometric N sweep: 100 -> 102400, ratio 2 (10 points)");
    spdlog::info("  {} --algorithm SM9Static --sweep --sweep-mode fixedRatio \\", progName);
    spdlog::info("      --n-start 100 --n-end 102400 --n-ratio 2");
    spdlog::info("");
    spdlog::info("  # Linear t sweep: 1..100, step 10 (10 points)");
    spdlog::info("  {} --algorithm DHTDynamic --sweep --sweep-mode fixedN \\", progName);
    spdlog::info("      --t-start 1 --t-end 100 --t-step 10 --r-values 50,100,200");
    spdlog::info("");
    spdlog::info("  # Dynamic PDP with 50 maintenance ops before audit");
    spdlog::info("  {} --algorithm DHTDynamic --maintenance-ops 50 \\", progName);
    spdlog::info("      --total-blocks 1000 --corrupted-blocks 5 --sample-size 100");
    spdlog::info("");
    spdlog::info("  # Single run with JSON output");
    spdlog::info("  {} --algorithm SM9Static --json report.json", progName);
    spdlog::info("");
    spdlog::info("  # List all available algorithms");
    spdlog::info("  {} --list-algorithms", progName);
}

/**
 * @brief List all registered algorithms grouped by strategy kind (Static / Dynamic)
 * @param strategyManager Strategy manager with registered strategies
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
    // ── Default parameters ──
    std::string algorithmType = "SM9Static";
    // Default strategy path: <exe_dir>/strategies (same convention as server config)
    namespace fs = std::filesystem;
    std::string defaultStrategyPath =
        (fs::path(argv[0]).parent_path() / "strategies").string();
    std::string strategyPath = defaultStrategyPath;
    std::size_t iterations = 10;
    std::size_t totalBlocks = 1000;
    std::size_t corruptedBlocks = 10;
    std::size_t sampleSize = 50;
    std::size_t maintenanceOps = 0;
    bool sweepMode = false;
    std::string sweepModeStr = "fixedN";
    std::string jsonPath;
    bool listAlgorithmsMode = false;
    double corruptedRatio = 0.0;
    double sampleRatio = 0.0;
    bool useCorruptedRatio = false;
    bool useSampleRatio = false;

    // ── Custom sweep axis inputs (empty => use default hardcoded list) ──
    // t axis
    std::string tValuesCsv;
    bool tStartSet = false, tEndSet = false, tStepSet = false, tRatioSet = false;
    std::size_t tStart = 0, tEnd = 0, tStep = 0;
    double tRatio = 2.0;
    // r axis
    std::string rValuesCsv;
    bool rStartSet = false, rEndSet = false, rStepSet = false, rRatioSet = false;
    std::size_t rStart = 0, rEnd = 0, rStep = 0;
    double rRatio = 2.0;
    // N axis (fixedRatio mode)
    std::string nValuesCsv;
    bool nStartSet = false, nEndSet = false, nStepSet = false, nRatioSet = false;
    std::size_t nStart = 0, nEnd = 0, nStep = 0;
    double nRatio = 2.0;

    // ── Parse command-line arguments ──
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algorithm" && i + 1 < argc) {
            algorithmType = argv[++i];
        } else if (arg == "--strategy-path" && i + 1 < argc) {
            strategyPath = argv[++i];
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--total-blocks" && i + 1 < argc) {
            totalBlocks = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--corrupted-blocks" && i + 1 < argc) {
            corruptedBlocks = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--sample-size" && i + 1 < argc) {
            sampleSize = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--maintenance-ops" && i + 1 < argc) {
            maintenanceOps = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--corrupted-ratio" && i + 1 < argc) {
            corruptedRatio = std::atof(argv[++i]);
            useCorruptedRatio = true;
        } else if (arg == "--sample-ratio" && i + 1 < argc) {
            sampleRatio = std::atof(argv[++i]);
            useSampleRatio = true;
        } else if (arg == "--sweep") {
            sweepMode = true;
        } else if (arg == "--sweep-mode" && i + 1 < argc) {
            sweepModeStr = argv[++i];
        } else if (arg == "--t-values" && i + 1 < argc) {
            tValuesCsv = argv[++i];
        } else if (arg == "--t-start" && i + 1 < argc) {
            tStart = static_cast<std::size_t>(std::atol(argv[++i])); tStartSet = true;
        } else if (arg == "--t-end" && i + 1 < argc) {
            tEnd = static_cast<std::size_t>(std::atol(argv[++i])); tEndSet = true;
        } else if (arg == "--t-step" && i + 1 < argc) {
            tStep = static_cast<std::size_t>(std::atol(argv[++i])); tStepSet = true;
        } else if (arg == "--t-ratio" && i + 1 < argc) {
            tRatio = std::atof(argv[++i]); tRatioSet = true;
        } else if (arg == "--r-values" && i + 1 < argc) {
            rValuesCsv = argv[++i];
        } else if (arg == "--r-start" && i + 1 < argc) {
            rStart = static_cast<std::size_t>(std::atol(argv[++i])); rStartSet = true;
        } else if (arg == "--r-end" && i + 1 < argc) {
            rEnd = static_cast<std::size_t>(std::atol(argv[++i])); rEndSet = true;
        } else if (arg == "--r-step" && i + 1 < argc) {
            rStep = static_cast<std::size_t>(std::atol(argv[++i])); rStepSet = true;
        } else if (arg == "--r-ratio" && i + 1 < argc) {
            rRatio = std::atof(argv[++i]); rRatioSet = true;
        } else if (arg == "--n-values" && i + 1 < argc) {
            nValuesCsv = argv[++i];
        } else if (arg == "--n-start" && i + 1 < argc) {
            nStart = static_cast<std::size_t>(std::atol(argv[++i])); nStartSet = true;
        } else if (arg == "--n-end" && i + 1 < argc) {
            nEnd = static_cast<std::size_t>(std::atol(argv[++i])); nEndSet = true;
        } else if (arg == "--n-step" && i + 1 < argc) {
            nStep = static_cast<std::size_t>(std::atol(argv[++i])); nStepSet = true;
        } else if (arg == "--n-ratio" && i + 1 < argc) {
            nRatio = std::atof(argv[++i]); nRatioSet = true;
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

    // ── Create InMemoryAuditStrategyManager ──
    auto strategyManager = std::make_shared<InMemoryAuditStrategyManager>();

    // ── Load all strategies (built-in and external) as plugins ──
    //    Built-in strategies are now hot-loaded from the strategy directory
    //    alongside third-party strategies. No hardcoded registration.
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
        // hotLoadDecorator is kept alive by the strategyManager's shared_ptr chain
        // via the decorator's inner_ member. The decorator itself will be destroyed
        // at end of scope, but its stopWatching() in the destructor cleanly shuts
        // down the watch thread.
    }

    // ── Validate target algorithm is available ──
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

    // ── Create PDP audit scenario ──
    auto scenario = std::make_unique<PdpAuditScenario>(algorithmType, strategyManager);

    // ── Run benchmark ──
    BenchmarkRunner runner(std::move(scenario));
    std::vector<BenchmarkResult> results;

    if (sweepMode) {
        // Parameter sweep mode

        // ── Helper: configure one axis from CLI inputs ──
        // Sources allowed (mutually exclusive):
        //   1) explicit CSV list
        //   2) linear generator (start + step)
        //   3) geometric generator (start + ratio)
        // Returns false on inconsistency (caller aborts).
        auto configureAxis = [](const std::string& csv,
                                 bool startSet, bool endSet, bool stepSet, bool ratioSet,
                                 std::size_t start, std::size_t end,
                                 std::size_t step, double ratio,
                                 std::vector<std::size_t>& explicitOut,
                                 SeqSpec& specOut) -> bool {
            int srcCount = !csv.empty() ? 1 : 0;
            srcCount += (startSet && stepSet) ? 1 : 0;
            srcCount += (startSet && ratioSet) ? 1 : 0;
            if (srcCount > 1) {
                spdlog::error("Conflicting axis sources: provide at most one of "
                              "explicit list / linear (start+step) / geometric (start+ratio).");
                return false;
            }
            if (startSet && !(stepSet || ratioSet)) {
                spdlog::error("--*-start given without --*-step or --*-ratio.");
                return false;
            }
            if ((stepSet && !startSet) || (ratioSet && !startSet)) {
                spdlog::error("--*-step/--*-ratio given without --*-start.");
                return false;
            }
            if (!endSet && (startSet && (stepSet || ratioSet))) {
                spdlog::error("--*-end is required when using a generator (linear/geometric).");
                return false;
            }

            if (!csv.empty()) {
                explicitOut = parseCsvSizeT(csv);
                if (explicitOut.empty()) {
                    spdlog::error("Failed to parse explicit list: '{}'", csv);
                    return false;
                }
                specOut.gen = SweepGen::Explicit;
                return true;
            }
            if (startSet && stepSet) {
                if (step == 0) {
                    spdlog::error("Linear step must be > 0.");
                    return false;
                }
                if (end < start) {
                    spdlog::error("Linear end ({}) < start ({}).", end, start);
                    return false;
                }
                specOut.gen = SweepGen::Linear;
                specOut.start = start;
                specOut.end = end;
                specOut.step = step;
                return true;
            }
            if (startSet && ratioSet) {
                if (ratio <= 1.0) {
                    spdlog::error("Geometric ratio must be > 1.0 (got {}).", ratio);
                    return false;
                }
                if (end < start) {
                    spdlog::error("Geometric end ({}) < start ({}).", end, start);
                    return false;
                }
                specOut.gen = SweepGen::Geometric;
                specOut.start = start;
                specOut.end = end;
                specOut.ratio = ratio;
                return true;
            }
            // No input for this axis: leave specOut as default (Explicit)
            // and explicitOut empty — expandSweep will fall back to the
            // caller-provided default list.
            return true;
        };

        ParameterSweep sweep;
        sweep.iterations = iterations;

        if (sweepModeStr == "fixedRatio") {
            sweep.mode = SweepMode::FixedRatio_ScanN;
            if (useCorruptedRatio) {
                sweep.corruptedRatio = corruptedRatio;
            } else {
                sweep.corruptedRatio = static_cast<double>(corruptedBlocks) /
                                       static_cast<double>(totalBlocks);
            }
            if (useSampleRatio) {
                sweep.sampleRatio = sampleRatio;
            } else {
                sweep.sampleRatio = static_cast<double>(sampleSize) /
                                    static_cast<double>(totalBlocks);
            }
            // N axis: default to hardcoded list if user gave no input
            sweep.nValues = {100, 500, 1000, 5000, 10000};
            sweep.blockSize = 256;
            sweep.maintenanceOps = maintenanceOps;

            if (!configureAxis(nValuesCsv,
                               nStartSet, nEndSet, nStepSet, nRatioSet,
                               nStart, nEnd, nStep, nRatio,
                               sweep.nValues, sweep.nSpec)) {
                return 1;
            }
        } else {
            // Default: fixedN mode
            sweep.mode = SweepMode::FixedN_ScanTR;
            sweep.fixedN = totalBlocks;
            // t / r axes: default to hardcoded lists if user gave no input
            sweep.tValues = {1, 5, 10, 50, 100};
            sweep.rValues = {10, 50, 100, 200};
            sweep.blockSize = 256;
            sweep.maintenanceOps = maintenanceOps;

            if (!configureAxis(tValuesCsv,
                               tStartSet, tEndSet, tStepSet, tRatioSet,
                               tStart, tEnd, tStep, tRatio,
                               sweep.tValues, sweep.tSpec)) {
                return 1;
            }
            if (!configureAxis(rValuesCsv,
                               rStartSet, rEndSet, rStepSet, rRatioSet,
                               rStart, rEnd, rStep, rRatio,
                               sweep.rValues, sweep.rSpec)) {
                return 1;
            }
        }

        // Final safety: ensure the resolved sweep produces at least one config
        auto probe = expandSweep(sweep);
        if (probe.empty()) {
            spdlog::error("Sweep produced 0 parameter combinations. Check axis ranges/generators.");
            return 1;
        }

        results = runner.runSweep(sweep);
    } else {
        // Single-run mode
        if (useCorruptedRatio) {
            corruptedBlocks = static_cast<std::size_t>(std::llround(corruptedRatio * static_cast<double>(totalBlocks)));
        }
        if (useSampleRatio) {
            sampleSize = static_cast<std::size_t>(std::llround(sampleRatio * static_cast<double>(totalBlocks)));
        }

        BenchmarkConfig config;
        config.totalBlocks = totalBlocks;
        config.corruptedBlocks = corruptedBlocks;
        config.sampleSize = sampleSize;
        config.iterations = iterations;
        config.blockSize = 256;
        config.maintenanceOps = maintenanceOps;

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
