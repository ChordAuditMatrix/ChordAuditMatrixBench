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
 * @file benchmark_computation_strategy.cpp
 * @brief ComputationStrategy implementations
 * @details Concrete parseAndExpand()/run()/createReport() for the four
 *          strategies, plus the strategy factory and the PDP-shared
 *          theoreticalConfidenceRate(). The inverse-sample-size solver
 *          (inverseSampleSize) lives in an anonymous namespace here.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
 */

#include <ChordAuditMatrixBench/benchmark_computation_strategy.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <spdlog/spdlog.h>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

// ==================================================================
// PDP-shared theoretical confidence rate (hypergeometric)
// ==================================================================

double theoreticalConfidenceRate(std::size_t totalBlocks,
                                  std::size_t corruptedBlocks,
                                  std::size_t sampleSize)
{
    if (totalBlocks == 0 || sampleSize == 0 || corruptedBlocks == 0) return 0.0;
    if (corruptedBlocks >= totalBlocks) return 1.0;
    if (sampleSize >= totalBlocks) return 1.0;
    if (sampleSize > totalBlocks - corruptedBlocks) return 1.0;

    double logRatio = 0.0;
    for (std::size_t i = 0; i < sampleSize; ++i) {
        double numerator = static_cast<double>(totalBlocks - corruptedBlocks - i);
        double denominator = static_cast<double>(totalBlocks - i);
        if (numerator <= 0.0) return 1.0;
        logRatio += std::log(numerator) - std::log(denominator);
    }
    return 1.0 - std::exp(logRatio);
}

namespace {

/// Parse a comma-separated list of non-negative integers
std::vector<std::size_t> parseCsvSizeT(const std::string& s)
{
    std::vector<std::size_t> out;
    if (s.empty()) return out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t j = s.find(',', i);
        std::string tok = (j == std::string::npos) ? s.substr(i) : s.substr(i, j - i);
        if (tok.empty()) return {};
        try {
            out.push_back(static_cast<std::size_t>(std::stoull(tok)));
        } catch (...) {
            return {};
        }
        if (j == std::string::npos) break;
        i = j + 1;
    }
    return out;
}

/// Strictly parse a non-negative unsigned CLI integer
/// @details Rejects signs, whitespace, trailing junk, and overflow — only
///          bare decimal digits are accepted (used for --threads).
bool parseStrictUnsigned(const std::string& text, std::size_t& out)
{
    if (text.empty()) return false;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
    }
    try {
        const unsigned long long v = std::stoull(text);
        if (v > static_cast<unsigned long long>(
                std::numeric_limits<std::size_t>::max())) {
            return false;
        }
        out = static_cast<std::size_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

/// Minimum sample size r (per N, t) to reach targetConfidence via the hypergeometric
std::size_t inverseSampleSize(std::size_t totalBlocks,
                               std::size_t corruptedBlocks,
                               double targetConfidence)
{
    if (totalBlocks == 0 || corruptedBlocks == 0 || targetConfidence <= 0.0) return 0;
    if (targetConfidence >= 1.0) return totalBlocks;
    if (corruptedBlocks >= totalBlocks) return 1;
    if (theoreticalConfidenceRate(totalBlocks, corruptedBlocks,
                                   totalBlocks - corruptedBlocks) < targetConfidence)
        return totalBlocks;
    std::size_t lo = 1, hi = totalBlocks - corruptedBlocks;
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        if (theoreticalConfidenceRate(totalBlocks, corruptedBlocks, mid) >= targetConfidence)
            hi = mid;
        else
            lo = mid + 1;
    }
    return lo;
}

/// Per-axis CLI source configuration (explicit CSV / linear / geometric)
struct AxisInput {
    std::string csv;
    bool startSet = false, endSet = false, stepSet = false, ratioSet = false;
    std::size_t start = 0, end = 0, step = 0;
    double ratio = 2.0;
};

/// Resolve an AxisInput into (explicit values, SeqSpec); returns false on conflict
bool resolveAxis(const AxisInput& in,
                 std::vector<std::size_t>& explicitOut,
                 SeqSpec& specOut)
{
    int srcCount = !in.csv.empty() ? 1 : 0;
    srcCount += (in.startSet && in.stepSet) ? 1 : 0;
    srcCount += (in.startSet && in.ratioSet) ? 1 : 0;
    if (srcCount > 1) {
        spdlog::error("Conflicting axis sources: provide at most one of "
                      "explicit list / linear (start+step) / geometric (start+ratio).");
        return false;
    }
    if (in.startSet && !(in.stepSet || in.ratioSet)) {
        spdlog::error("--*-start given without --*-step or --*-ratio.");
        return false;
    }
    if ((in.stepSet && !in.startSet) || (in.ratioSet && !in.startSet)) {
        spdlog::error("--*-step/--*-ratio given without --*-start.");
        return false;
    }
    if (!in.endSet && (in.startSet && (in.stepSet || in.ratioSet))) {
        spdlog::error("--*-end is required when using a generator (linear/geometric).");
        return false;
    }

    if (!in.csv.empty()) {
        explicitOut = parseCsvSizeT(in.csv);
        if (explicitOut.empty()) {
            spdlog::error("Failed to parse explicit list: '{}'", in.csv);
            return false;
        }
        specOut.gen = SweepGen::Explicit;
        return true;
    }
    if (in.startSet && in.stepSet) {
        if (in.step == 0) { spdlog::error("Linear step must be > 0."); return false; }
        if (in.end < in.start) { spdlog::error("Linear end ({}) < start ({}).", in.end, in.start); return false; }
        specOut.gen = SweepGen::Linear;
        specOut.start = in.start; specOut.end = in.end; specOut.step = in.step;
        return true;
    }
    if (in.startSet && in.ratioSet) {
        if (in.ratio <= 1.0) { spdlog::error("Geometric ratio must be > 1.0 (got {}).", in.ratio); return false; }
        if (in.end < in.start) { spdlog::error("Geometric end ({}) < start ({}).", in.end, in.start); return false; }
        specOut.gen = SweepGen::Geometric;
        specOut.start = in.start; specOut.end = in.end; specOut.ratio = in.ratio;
        return true;
    }
    return true; // no input — caller falls back to defaults
}

/// Shared PDP run() body: runSingle + fill theoreticalConfidenceRate
std::unique_ptr<BenchmarkResult> pdpRun(BenchmarkRunner& runner, const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const PdpAuditConfig&>(config);
    auto result = runner.runSingle(cfg);
    auto* pdp = dynamic_cast<PdpAuditResult*>(result.get());
    if (pdp) {
        pdp->theoreticalConfidenceRate = theoreticalConfidenceRate(
            cfg.totalBlocks, cfg.corruptedBlocks, cfg.sampleSize);
        spdlog::info("confidence={:.2f} theoretical={:.2f}",
                     pdp->confidenceRate, pdp->theoreticalConfidenceRate);
    }
    return result;
}

} // anonymous namespace

// ==================================================================
// PdpDirectStrategy
// ==================================================================

std::vector<std::unique_ptr<BenchmarkConfig>>
PdpDirectStrategy::parseAndExpand(int argc, char** argv)
{
    // Defaults
    std::size_t totalBlocks = 1000;
    std::size_t iterations = 10;
    std::size_t threads = 1;
    std::size_t blockSize = 256;
    std::size_t maintenanceOps = 0;
    bool usePseudoRandom = false;
    std::uint64_t seed = 0;

    AxisInput tAxis, rAxis;
    bool singleT = false; std::size_t tVal = 10;
    bool singleR = false; std::size_t rVal = 50;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--total-blocks" && i + 1 < argc) {
            totalBlocks = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parseStrictUnsigned(argv[++i], threads)) {
                spdlog::error("Invalid --threads value '{}': expected a non-negative integer.",
                              argv[i]);
                return {};
            }
        } else if (arg == "--block-size" && i + 1 < argc) {
            blockSize = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--maintenance-ops" && i + 1 < argc) {
            maintenanceOps = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--use-pseudo-random") {
            usePseudoRandom = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            usePseudoRandom = true;
        } else if (arg == "--corrupted-blocks" && i + 1 < argc) {
            tVal = static_cast<std::size_t>(std::atol(argv[++i])); singleT = true;
        } else if (arg == "--sample-size" && i + 1 < argc) {
            rVal = static_cast<std::size_t>(std::atol(argv[++i])); singleR = true;
        } else if (arg == "--t-values" && i + 1 < argc) {
            tAxis.csv = argv[++i];
        } else if (arg == "--t-start" && i + 1 < argc) {
            tAxis.start = static_cast<std::size_t>(std::atol(argv[++i])); tAxis.startSet = true;
        } else if (arg == "--t-end" && i + 1 < argc) {
            tAxis.end = static_cast<std::size_t>(std::atol(argv[++i])); tAxis.endSet = true;
        } else if (arg == "--t-step" && i + 1 < argc) {
            tAxis.step = static_cast<std::size_t>(std::atol(argv[++i])); tAxis.stepSet = true;
        } else if (arg == "--t-ratio" && i + 1 < argc) {
            tAxis.ratio = std::atof(argv[++i]); tAxis.ratioSet = true;
        } else if (arg == "--r-values" && i + 1 < argc) {
            rAxis.csv = argv[++i];
        } else if (arg == "--r-start" && i + 1 < argc) {
            rAxis.start = static_cast<std::size_t>(std::atol(argv[++i])); rAxis.startSet = true;
        } else if (arg == "--r-end" && i + 1 < argc) {
            rAxis.end = static_cast<std::size_t>(std::atol(argv[++i])); rAxis.endSet = true;
        } else if (arg == "--r-step" && i + 1 < argc) {
            rAxis.step = static_cast<std::size_t>(std::atol(argv[++i])); rAxis.stepSet = true;
        } else if (arg == "--r-ratio" && i + 1 < argc) {
            rAxis.ratio = std::atof(argv[++i]); rAxis.ratioSet = true;
        }
        // Unknown args are silently skipped (algorithm/path/json handled by main)
    }

    // Resolve t / r axes
    std::vector<std::size_t> tVals, rVals;
    SeqSpec tSpec, rSpec;
    if (singleT && tAxis.csv.empty() && !tAxis.startSet) {
        tVals = { tVal };
    } else {
        if (tVals.empty()) tVals = {1, 5, 10, 50, 100}; // default list
        if (!resolveAxis(tAxis, tVals, tSpec)) return {};
    }
    if (singleR && rAxis.csv.empty() && !rAxis.startSet) {
        rVals = { rVal };
    } else {
        if (rVals.empty()) rVals = {10, 50, 100, 200}; // default list
        if (!resolveAxis(rAxis, rVals, rSpec)) return {};
    }
    tVals = resolveSeq(tVals, tSpec);
    rVals = resolveSeq(rVals, rSpec);

    std::vector<std::unique_ptr<BenchmarkConfig>> configs;
    for (auto t : tVals) {
        for (auto r : rVals) {
            auto cfg = std::make_unique<PdpAuditConfig>();
            cfg->totalBlocks = totalBlocks;
            cfg->corruptedBlocks = t;
            cfg->sampleSize = r;
            cfg->blockSize = blockSize;
            cfg->maintenanceOps = maintenanceOps;
            cfg->iterations = iterations;
            cfg->threads = threads;
            cfg->usePseudoRandom = usePseudoRandom;
            cfg->seed = seed;
            configs.push_back(std::move(cfg));
        }
    }
    return configs;
}

std::unique_ptr<BenchmarkResult> PdpDirectStrategy::run(
    BenchmarkRunner& runner, const BenchmarkConfig& config)
{
    return pdpRun(runner, config);
}

std::unique_ptr<Report> PdpDirectStrategy::createReport(
    const std::vector<std::unique_ptr<BenchmarkResult>>& results,
    const std::string& algorithmType) const
{
    return std::make_unique<PdpDirectReport>(results, algorithmType);
}

// ==================================================================
// PdpFixedRatioStrategy
// ==================================================================

std::vector<std::unique_ptr<BenchmarkConfig>>
PdpFixedRatioStrategy::parseAndExpand(int argc, char** argv)
{
    std::size_t iterations = 10;
    std::size_t threads = 1;
    std::size_t blockSize = 256;
    std::size_t maintenanceOps = 0;
    bool usePseudoRandom = false;
    std::uint64_t seed = 0;
    double corruptedRatio = 0.01;
    double sampleRatio = 0.05;

    AxisInput nAxis;
    std::string nValuesCsv;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parseStrictUnsigned(argv[++i], threads)) {
                spdlog::error("Invalid --threads value '{}': expected a non-negative integer.",
                              argv[i]);
                return {};
            }
        } else if (arg == "--block-size" && i + 1 < argc) {
            blockSize = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--maintenance-ops" && i + 1 < argc) {
            maintenanceOps = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--use-pseudo-random") {
            usePseudoRandom = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            usePseudoRandom = true;
        } else if (arg == "--corrupted-ratio" && i + 1 < argc) {
            corruptedRatio = std::atof(argv[++i]);
        } else if (arg == "--sample-ratio" && i + 1 < argc) {
            sampleRatio = std::atof(argv[++i]);
        } else if (arg == "--n-values" && i + 1 < argc) {
            nAxis.csv = argv[++i];
        } else if (arg == "--n-start" && i + 1 < argc) {
            nAxis.start = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.startSet = true;
        } else if (arg == "--n-end" && i + 1 < argc) {
            nAxis.end = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.endSet = true;
        } else if (arg == "--n-step" && i + 1 < argc) {
            nAxis.step = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.stepSet = true;
        } else if (arg == "--n-ratio" && i + 1 < argc) {
            nAxis.ratio = std::atof(argv[++i]); nAxis.ratioSet = true;
        }
    }

    std::vector<std::size_t> nVals = {100, 500, 1000, 5000, 10000};
    SeqSpec nSpec;
    if (!resolveAxis(nAxis, nVals, nSpec)) return {};
    nVals = resolveSeq(nVals, nSpec);

    std::vector<std::unique_ptr<BenchmarkConfig>> configs;
    for (auto n : nVals) {
        auto cfg = std::make_unique<PdpAuditConfig>();
        cfg->totalBlocks = n;
        cfg->corruptedBlocks = std::max<std::size_t>(1, static_cast<std::size_t>(n * corruptedRatio));
        cfg->sampleSize = std::max<std::size_t>(1, static_cast<std::size_t>(n * sampleRatio));
        cfg->sampleSize = std::min(cfg->sampleSize, cfg->totalBlocks);
        cfg->corruptedBlocks = std::min(cfg->corruptedBlocks, cfg->totalBlocks);
        cfg->blockSize = blockSize;
        cfg->maintenanceOps = maintenanceOps;
        cfg->iterations = iterations;
        cfg->threads = threads;
        cfg->usePseudoRandom = usePseudoRandom;
        cfg->seed = seed;
        configs.push_back(std::move(cfg));
    }
    return configs;
}

std::unique_ptr<BenchmarkResult> PdpFixedRatioStrategy::run(
    BenchmarkRunner& runner, const BenchmarkConfig& config)
{
    return pdpRun(runner, config);
}

std::unique_ptr<Report> PdpFixedRatioStrategy::createReport(
    const std::vector<std::unique_ptr<BenchmarkResult>>& results,
    const std::string& algorithmType) const
{
    return std::make_unique<PdpFixedRatioReport>(results, algorithmType);
}

// ==================================================================
// PdpInverseConfidenceStrategy
// ==================================================================

std::vector<std::unique_ptr<BenchmarkConfig>>
PdpInverseConfidenceStrategy::parseAndExpand(int argc, char** argv)
{
    std::size_t iterations = 10;
    std::size_t threads = 1;
    std::size_t blockSize = 256;
    std::size_t maintenanceOps = 0;
    bool usePseudoRandom = false;
    std::uint64_t seed = 0;
    double targetConfidence = 0.96;
    double corruptedRatio = 0.02;

    AxisInput nAxis;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parseStrictUnsigned(argv[++i], threads)) {
                spdlog::error("Invalid --threads value '{}': expected a non-negative integer.",
                              argv[i]);
                return {};
            }
        } else if (arg == "--block-size" && i + 1 < argc) {
            blockSize = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--maintenance-ops" && i + 1 < argc) {
            maintenanceOps = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--use-pseudo-random") {
            usePseudoRandom = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            usePseudoRandom = true;
        } else if (arg == "--target-confidence" && i + 1 < argc) {
            targetConfidence = std::atof(argv[++i]);
        } else if (arg == "--corrupted-ratio" && i + 1 < argc) {
            corruptedRatio = std::atof(argv[++i]);
        } else if (arg == "--n-values" && i + 1 < argc) {
            nAxis.csv = argv[++i];
        } else if (arg == "--n-start" && i + 1 < argc) {
            nAxis.start = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.startSet = true;
        } else if (arg == "--n-end" && i + 1 < argc) {
            nAxis.end = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.endSet = true;
        } else if (arg == "--n-step" && i + 1 < argc) {
            nAxis.step = static_cast<std::size_t>(std::atol(argv[++i])); nAxis.stepSet = true;
        } else if (arg == "--n-ratio" && i + 1 < argc) {
            nAxis.ratio = std::atof(argv[++i]); nAxis.ratioSet = true;
        }
    }

    std::vector<std::size_t> nVals = {100, 500, 1000, 5000, 10000};
    SeqSpec nSpec;
    if (!resolveAxis(nAxis, nVals, nSpec)) return {};
    nVals = resolveSeq(nVals, nSpec);

    std::vector<std::unique_ptr<BenchmarkConfig>> configs;
    for (auto n : nVals) {
        std::size_t t = std::max<std::size_t>(1, static_cast<std::size_t>(n * corruptedRatio));
        t = std::min(t, n);
        std::size_t r = inverseSampleSize(n, t, targetConfidence);
        auto cfg = std::make_unique<PdpAuditConfig>();
        cfg->totalBlocks = n;
        cfg->corruptedBlocks = t;
        cfg->sampleSize = r;
        cfg->blockSize = blockSize;
        cfg->maintenanceOps = maintenanceOps;
        cfg->iterations = iterations;
        cfg->threads = threads;
        cfg->usePseudoRandom = usePseudoRandom;
        cfg->seed = seed;
        configs.push_back(std::move(cfg));
    }
    return configs;
}

std::unique_ptr<BenchmarkResult> PdpInverseConfidenceStrategy::run(
    BenchmarkRunner& runner, const BenchmarkConfig& config)
{
    return pdpRun(runner, config);
}

std::unique_ptr<Report> PdpInverseConfidenceStrategy::createReport(
    const std::vector<std::unique_ptr<BenchmarkResult>>& results,
    const std::string& algorithmType) const
{
    return std::make_unique<PdpInverseConfidenceReport>(results, algorithmType);
}

// ==================================================================
// IdentityVerifyStrategy
// ==================================================================

std::vector<std::unique_ptr<BenchmarkConfig>>
IdentityVerifyStrategy::parseAndExpand(int argc, char** argv)
{
    std::size_t iterations = 10;
    std::size_t threads = 1;
    std::size_t numUsers = 10;
    std::size_t samplesPerIteration = 20;
    double forgeryRatio = 0.0;
    double tamperedRatio = 0.5;
    double impersonationRatio = 0.0;
    bool usePseudoRandom = false;
    std::uint64_t seed = 0;
    bool sweepMode = false;

    AxisInput userAxis;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parseStrictUnsigned(argv[++i], threads)) {
                spdlog::error("Invalid --threads value '{}': expected a non-negative integer.",
                              argv[i]);
                return {};
            }
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
        } else if (arg == "--use-pseudo-random") {
            usePseudoRandom = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            usePseudoRandom = true;
        } else if (arg == "--sweep") {
            sweepMode = true;
        } else if (arg == "--user-values" && i + 1 < argc) {
            userAxis.csv = argv[++i];
        } else if (arg == "--user-start" && i + 1 < argc) {
            userAxis.start = static_cast<std::size_t>(std::atol(argv[++i])); userAxis.startSet = true;
        } else if (arg == "--user-end" && i + 1 < argc) {
            userAxis.end = static_cast<std::size_t>(std::atol(argv[++i])); userAxis.endSet = true;
        } else if (arg == "--user-step" && i + 1 < argc) {
            userAxis.step = static_cast<std::size_t>(std::atol(argv[++i])); userAxis.stepSet = true;
        } else if (arg == "--user-ratio" && i + 1 < argc) {
            userAxis.ratio = std::atof(argv[++i]); userAxis.ratioSet = true;
        }
    }

    // Validate negative sample ratios
    double totalNeg = forgeryRatio + tamperedRatio + impersonationRatio;
    if (totalNeg > 1.0) {
        spdlog::error("Sum of negative sample ratios ({}) exceeds 1.0.", totalNeg);
        return {};
    }

    std::vector<std::unique_ptr<BenchmarkConfig>> configs;

    auto makeCfg = [&](std::size_t users) {
        auto cfg = std::make_unique<IdentityConfig>();
        cfg->numUsers = users;
        cfg->samplesPerIteration = samplesPerIteration;
        cfg->negativeSamples.forgeryRatio = forgeryRatio;
        cfg->negativeSamples.tamperedRatio = tamperedRatio;
        cfg->negativeSamples.impersonationRatio = impersonationRatio;
        cfg->iterations = iterations;
        cfg->threads = threads;
        cfg->usePseudoRandom = usePseudoRandom;
        cfg->seed = seed;
        return cfg;
    };

    if (sweepMode) {
        std::vector<std::size_t> userVals = {1, 5, 10, 50, 100, 500, 1000};
        SeqSpec userSpec;
        if (!resolveAxis(userAxis, userVals, userSpec)) return {};
        userVals = resolveSeq(userVals, userSpec);
        for (auto u : userVals) {
            if (u < 2) {
                spdlog::warn("Skipping user-count point {}: identity verification requires >=2 users "
                             "to construct forgery/impersonation samples.", u);
                continue;
            }
            configs.push_back(makeCfg(u));
        }
    } else {
        if (numUsers < 2) {
            spdlog::warn("num-users={} < 2: forgery/impersonation samples cannot be constructed "
                         "with a single user (no other user to impersonate).", numUsers);
        }
        configs.push_back(makeCfg(numUsers));
    }
    return configs;
}

std::unique_ptr<BenchmarkResult> IdentityVerifyStrategy::run(
    BenchmarkRunner& runner, const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const IdentityConfig&>(config);
    auto result = runner.runSingle(cfg);
    auto* id = dynamic_cast<IdentityResult*>(result.get());
    if (id) {
        spdlog::info(
            "accuracy={:.2f} (TP/iter={:.2f} FP/iter={:.2f} TN/iter={:.2f} FN/iter={:.2f}; "
            "totals TP={} FP={} TN={} FN={})",
            id->accuracyRate, id->averageTrueAccepts,
            id->averageFalseAccepts, id->averageTrueRejects,
            id->averageFalseRejects, id->trueAccepts,
            id->falseAccepts, id->trueRejects, id->falseRejects);
    }
    return result;
}

std::unique_ptr<Report> IdentityVerifyStrategy::createReport(
    const std::vector<std::unique_ptr<BenchmarkResult>>& results,
    const std::string& algorithmType) const
{
    return std::make_unique<IdentityReport>(results, algorithmType);
}

// ==================================================================
// Factory
// ==================================================================

std::unique_ptr<ComputationStrategy> createComputationStrategy(const std::string& type)
{
    if (type == "PdpDirect")               return std::make_unique<PdpDirectStrategy>();
    if (type == "PdpFixedRatio")           return std::make_unique<PdpFixedRatioStrategy>();
    if (type == "PdpInverseConfidence")    return std::make_unique<PdpInverseConfidenceStrategy>();
    if (type == "IdentityVerify")          return std::make_unique<IdentityVerifyStrategy>();
    return nullptr;
}

} // namespace CAMatrix::Audit::Benchmark
