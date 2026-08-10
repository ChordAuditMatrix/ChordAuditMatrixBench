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
 * @file benchmark_computation_strategy.h
 * @brief Polymorphic computation-strategy hierarchy
 * @details Defines ComputationStrategy (abstract base) with three pure-virtual
 *          methods — parseAndExpand() / run() / createReport() — and four
 *          concrete strategies: PdpDirectStrategy, PdpFixedRatioStrategy,
 *          PdpInverseConfidenceStrategy, IdentityVerifyStrategy.
 *
 *          parseAndExpand() and createReport() are virtual and return base-class
 *          pointers so the CLI can hold a single `unique_ptr<ComputationStrategy>`
 *          and call the entire pipeline polymorphically (zero if/else). The
 *          theoreticalConfidenceRate() helper is declared here (defined in the
 *          .cpp) since it is shared by the three PDP strategies.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_COMPUTATION_STRATEGY_H
#define CAMATRIX_AUDIT_BENCHMARK_COMPUTATION_STRATEGY_H

#include <ChordAuditMatrixBench/benchmark_config.h>
#include <ChordAuditMatrixBench/benchmark_report.h>
#include <ChordAuditMatrixBench/benchmark_runner.h>
#include <ChordAuditMatrixBench/benchmark_types.h>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @brief Theoretical PDP confidence rate from the hypergeometric distribution
 * @details P = 1 - C(N-t, r) / C(N, r) computed in log-space to avoid overflow.
 *          Shared by the three PDP strategies' run() methods.
 * @param totalBlocks Total number of data blocks (N)
 * @param corruptedBlocks Number of corrupted blocks (t)
 * @param sampleSize Number of challenged blocks (r)
 * @return Theoretical detection probability in [0, 1]
 */
double theoreticalConfidenceRate(std::size_t totalBlocks,
                                  std::size_t corruptedBlocks,
                                  std::size_t sampleSize);

/**
 * @class ComputationStrategy
 * @brief Abstract base for all computation strategies
 * @details Each strategy owns: (1) CLI argument parsing + sweep expansion,
 *          (2) execution via the runner, (3) report construction. All three
 *          methods are virtual so the CLI main holds a single base pointer and
 *          dispatches polymorphically.
 */
class ComputationStrategy {
public:
    virtual ~ComputationStrategy() = default;

    /// @brief Strategy type identifier (matches CLI --computation value)
    /// @return Strategy type string
    virtual std::string type() const = 0;

    /**
     * @brief Parse CLI arguments and expand into a list of typed configs
     * @details Returns base-class pointers; each concrete strategy internally
     *          constructs PdpAuditConfig or IdentityConfig instances.
     * @param argc Argument count from main()
     * @param argv Argument vector from main()
     * @return Vector of owned, typed benchmark configurations
     */
    virtual std::vector<std::unique_ptr<BenchmarkConfig>> parseAndExpand(
        int argc, char** argv) = 0;

    /**
     * @brief Execute a single benchmark run
     * @details Dispatches to runner.runSingle(config) and, for PDP strategies,
     *          fills theoreticalConfidenceRate on the result.
     * @param runner Benchmark runner owning the scenario
     * @param config Benchmark configuration for this run
     * @return Polymorphic benchmark result
     */
    virtual std::unique_ptr<BenchmarkResult> run(
        BenchmarkRunner& runner, const BenchmarkConfig& config) = 0;

    /**
     * @brief Build the strategy-appropriate Report from results
     * @param results Aggregated benchmark results
     * @param algorithmType Algorithm type label for the report
     * @return Owned, strategy-specific Report
     */
    virtual std::unique_ptr<Report> createReport(
        const std::vector<std::unique_ptr<BenchmarkResult>>& results,
        const std::string& algorithmType) const = 0;
};

// ==================================================================
// Concrete strategies
// ==================================================================

/**
 * @class PdpDirectStrategy
 * @brief PDP benchmark with explicit (N, t, r) values or t/r sweeps at fixed N
 */
class PdpDirectStrategy : public ComputationStrategy {
public:
    std::string type() const override { return "PdpDirect"; }
    std::vector<std::unique_ptr<BenchmarkConfig>> parseAndExpand(int argc, char** argv) override;
    std::unique_ptr<BenchmarkResult> run(
        BenchmarkRunner& runner, const BenchmarkConfig& config) override;
    std::unique_ptr<Report> createReport(
        const std::vector<std::unique_ptr<BenchmarkResult>>& results,
        const std::string& algorithmType) const override;
};

/**
 * @class PdpFixedRatioStrategy
 * @brief PDP benchmark with fixed t/N and r/N ratios, scanning N values
 */
class PdpFixedRatioStrategy : public ComputationStrategy {
public:
    std::string type() const override { return "PdpFixedRatio"; }
    std::vector<std::unique_ptr<BenchmarkConfig>> parseAndExpand(int argc, char** argv) override;
    std::unique_ptr<BenchmarkResult> run(
        BenchmarkRunner& runner, const BenchmarkConfig& config) override;
    std::unique_ptr<Report> createReport(
        const std::vector<std::unique_ptr<BenchmarkResult>>& results,
        const std::string& algorithmType) const override;
};

/**
 * @class PdpInverseConfidenceStrategy
 * @brief PDP benchmark: for a target confidence P* and corruption ratio, solve
 *        the minimum sample size r per N via binary search on the hypergeometric.
 */
class PdpInverseConfidenceStrategy : public ComputationStrategy {
public:
    std::string type() const override { return "PdpInverseConfidence"; }
    std::vector<std::unique_ptr<BenchmarkConfig>> parseAndExpand(int argc, char** argv) override;
    std::unique_ptr<BenchmarkResult> run(
        BenchmarkRunner& runner, const BenchmarkConfig& config) override;
    std::unique_ptr<Report> createReport(
        const std::vector<std::unique_ptr<BenchmarkResult>>& results,
        const std::string& algorithmType) const override;
};

/**
 * @class IdentityVerifyStrategy
 * @brief Identity verification benchmark scanning user counts
 */
class IdentityVerifyStrategy : public ComputationStrategy {
public:
    std::string type() const override { return "IdentityVerify"; }
    std::vector<std::unique_ptr<BenchmarkConfig>> parseAndExpand(int argc, char** argv) override;
    std::unique_ptr<BenchmarkResult> run(
        BenchmarkRunner& runner, const BenchmarkConfig& config) override;
    std::unique_ptr<Report> createReport(
        const std::vector<std::unique_ptr<BenchmarkResult>>& results,
        const std::string& algorithmType) const override;
};

/**
 * @brief Factory: create a strategy by CLI --computation value
 * @param type Strategy type string ("PdpDirect" / "PdpFixedRatio" /
 *             "PdpInverseConfidence" / "IdentityVerify")
 * @return Owned strategy, or nullptr if type is unknown
 */
std::unique_ptr<ComputationStrategy> createComputationStrategy(const std::string& type);

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_COMPUTATION_STRATEGY_H
