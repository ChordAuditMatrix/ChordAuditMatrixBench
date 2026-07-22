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
 * @file pdp_audit_scenario.cpp
 * @brief PDP audit benchmark scenario implementation
 * @details Concrete implementation of BenchmarkScenario for PDP audit
 *          algorithms. Uses AuditStrategyManager for algorithm-agnostic strategy
 *          resolution, AuditEngine for the 7-stage pipeline, and
 *          MemoryAuditBlockSource for deterministic data generation.
 *
 *          Static PDP pipeline:
 *          - Setup: initAlgo → genKeys → genTags
 *          - Corruption: flip bits in selected blocks while keeping Tags unchanged
 *          - Iteration: genChallenges → genProofs → verifyProofs
 *
 *          Dynamic PDP pipeline:
 *          - Setup: initAlgo → genKeys → genTags → inject StateStore → maintenance ops
 *          - Stale versions: mark blocks as stale in StateStore (version mismatch)
 *          - Iteration: genChallenges → genProofs → verifyProofs
 *
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-08
 */

#include <ChordAuditMatrixBench/pdp_audit_scenario.h>

// ── Framework ──
#include <ChordAuditMatrixBench/benchmark_types.h>

// ── Engine interface ──
#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/interfaces/audit/operation_context.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tags.h"

// ── Strategy manager ──
#include "ChordAuditMatrixLib/interfaces/audit/audit_strategy_manager.h"
#include "ChordAuditMatrixLib/interfaces/audit/strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"

// ── Dynamic PDP state store ──
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_hash_table_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/versioned_block_metadata.h"

// ── Block source ──
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_source.h"

#include <json/json.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

namespace {

/// Namespace aliases for concise engine/strategy references
namespace AuditCore = CAMatrix::Audit::Core;
namespace AuditMsg  = CAMatrix::Audit::Messages;
namespace AuditData = CAMatrix::Audit::Data;

/// Helper: create a JSON RawInput from a Json::Value
AuditMsg::RawInput jsonInput(const ::Json::Value& v)
{
    return AuditMsg::RawInput(
        std::make_shared<std::string>(::Json::FastWriter().write(v)));
}

/// Helper: measure elapsed time in milliseconds for a callable
template <typename Func>
double measureMs(Func&& fn)
{
    auto start = std::chrono::steady_clock::now();
    std::forward<Func>(fn)();
    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

} // anonymous namespace

// ==================================================================
// PdpAuditScenario — Construction
// ==================================================================

PdpAuditScenario::PdpAuditScenario(
    const std::string& algorithmType,
    std::shared_ptr<AuditCore::AuditStrategyManager> strategyManager)
    : algorithmType_(algorithmType)
    , strategyManager_(std::move(strategyManager))
{
}

// ==================================================================
// PdpAuditScenario — BenchmarkScenario interface
// ==================================================================

std::string PdpAuditScenario::algorithmType() const
{
    return algorithmType_;
}

// ==================================================================
// PdpAuditScenario — setup
// ==================================================================

void PdpAuditScenario::setup(const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const PdpAuditConfig&>(config);
    config_ = cfg;

    // Step 1: Resolve strategy from AuditStrategyManager
    if (!strategyManager_ || !strategyManager_->hasAlgorithm(algorithmType_)) {
        throw std::invalid_argument(
            "PdpAuditScenario: strategy not found for algorithm type '" +
            algorithmType_ + "'");
    }
    auto strategy = strategyManager_->getStrategy(algorithmType_);

    // Cache strategy kind for O(1) dispatch in subsequent operations
    ctx_.strategyKind = strategy->kind();

    // Step 2: Create engine and set strategy
    ctx_.engine = AuditCore::AuditEngineFactory::createInstance();
    ctx_.engine->setStrategy(strategy);

    ctx_.opCtx = std::make_unique<AuditCore::AuditOperationContext>();

    // Step 3: Generate deterministic data blocks
    ctx_.userId = "benchmark@" + algorithmType_;
    ctx_.fileId = "file-benchmark-" + algorithmType_;

    std::uint64_t blockSeed = config.usePseudoRandom ? config.seed : 42;
    ctx_.originalBlocks = makeBlockSource(cfg.totalBlocks, cfg.blockSize, blockSeed);
    // Initially, corruptedBlocks equals original (no corruption yet)
    ctx_.corruptedBlocks = ctx_.originalBlocks;

    // Step 4: Initialize algorithm
    ctx_.setupTimings.initAlgoMs = measureMs([&]() {
        ctx_.engine->initializeAlgorithm(AuditMsg::RawInput(), *ctx_.opCtx);
    });

    // Step 5: Generate keys
    ::Json::Value keyJson;
    keyJson["userId"] = ctx_.userId;
    ctx_.setupTimings.genKeysMs = measureMs([&]() {
        ctx_.engine->generateKeys(jsonInput(keyJson), *ctx_.opCtx);
    });

    // Step 6 (dynamic PDP only): Inject StateStore BEFORE tag generation
    // so that generateTags can read per-block metadata (version, timestamp)
    // from the stateStore for computeBlockHash.
    if (ctx_.strategyKind == AuditCore::StrategyKind::Dynamic) {
        auto dynStrategy = std::dynamic_pointer_cast<AuditCore::DynamicAuditStrategy>(strategy);
        if (!dynStrategy) {
            throw std::logic_error(
                "PdpAuditScenario: strategy kind is Dynamic but dynamic_pointer_cast failed");
        }

        // Create and inject DynamicHashTableStateStore with bulk initialization
        // This creates all blocks with default metadata (version=1, timestamp=0)
        auto stateStore = std::make_shared<AuditCore::DynamicHashTableStateStore>();
        stateStore->addFile(ctx_.fileId, cfg.totalBlocks);

        dynStrategy->setStateStore(stateStore);
        // Keep a reference in context for direct access (avoids protected stateStore() getter)
        ctx_.stateStore = stateStore;
    }

    // Step 7: Generate tags from original blocks
    // (stateStore must already be injected for dynamic PDP so that
    //  computeBlockHash can read version/timestamp metadata)
    auto tagsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(ctx_.originalBlocks));
    tagsDataMap->emplace("fileId", ctx_.fileId);
    tagsDataMap->emplace("userId", ctx_.userId);
    ctx_.setupTimings.genTagsMs = measureMs([&]() {
        ctx_.engine->generateTags(AuditMsg::RawInput(tagsDataMap), *ctx_.opCtx);
    });

    // Store tags from context
    ctx_.tags = ctx_.opCtx->generateTagsResult->tags;

    // Step 8 (dynamic PDP only): Perform maintenance operations
    if (ctx_.strategyKind == AuditCore::StrategyKind::Dynamic) {
        if (cfg.maintenanceOps > 0) {
            std::mt19937 rng(config.usePseudoRandom ? config.seed + 2 : 123);
            std::uniform_int_distribution<std::size_t> blockIdxDist(0, cfg.totalBlocks - 1);
            // MaintenanceOpType distribution: Update=0, Insert=1, Delete=2
            std::uniform_int_distribution<int> opTypeDist(0, 2);

            for (std::size_t op = 0; op < cfg.maintenanceOps; ++op) {
                auto blockIdx = blockIdxDist(rng);
                auto opType = static_cast<AuditMsg::MaintenanceOpType>(opTypeDist(rng));

                // Build JSON maintenance request (createRequest expects JSON with blockIndices array)
                ::Json::Value maintainJson;
                maintainJson["fileId"] = ctx_.fileId;
                maintainJson["opType"] = static_cast<int>(opType);
                maintainJson["blockIndices"] = ::Json::Value(::Json::arrayValue);
                maintainJson["blockIndices"].append(static_cast<::Json::UInt64>(blockIdx));

                // For Insert, we need pre-generated tags for the new block
                if (opType == AuditMsg::MaintenanceOpType::Insert) {
                    // Generate a single new block and its tag
                    auto newBlockData = std::vector<std::uint8_t>(cfg.blockSize, 0xAB);
                    auto newBlockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(
                        std::vector<std::vector<std::uint8_t>>{newBlockData},
                        cfg.blockSize, 0);

                    // Generate tag for the new block
                    auto newTagsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
                    newTagsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(newBlockSource));
                    newTagsDataMap->emplace("fileId", ctx_.fileId);
                    newTagsDataMap->emplace("userId", ctx_.userId);

                    AuditCore::AuditOperationContext maintainCtx;
                    maintainCtx.initializeAlgorithmResult = ctx_.opCtx->initializeAlgorithmResult;
                    maintainCtx.generateKeysResult = ctx_.opCtx->generateKeysResult;

                    ctx_.engine->generateTags(AuditMsg::RawInput(newTagsDataMap), maintainCtx);

                    ctx_.setupTimings.maintainMs += measureMs([&]() {
                        ctx_.engine->maintain(jsonInput(maintainJson), maintainCtx);
                    });
                } else {
                    // Update or Delete — no new tags needed, just JSON request
                    AuditCore::AuditOperationContext maintainCtx;
                    maintainCtx.initializeAlgorithmResult = ctx_.opCtx->initializeAlgorithmResult;
                    maintainCtx.generateKeysResult = ctx_.opCtx->generateKeysResult;

                    ctx_.setupTimings.maintainMs += measureMs([&]() {
                        ctx_.engine->maintain(jsonInput(maintainJson), maintainCtx);
                    });
                }
            }
        }
    }
}

// ==================================================================
// PdpAuditScenario — corruptBlocks
// ==================================================================

void PdpAuditScenario::corruptBlocks(std::size_t t)
{
    if (t == 0) return;

    std::uint64_t corruptSeed = config_.usePseudoRandom ? config_.seed + 1 : 0;
    auto result = corruptBlockSource(ctx_.originalBlocks, t, corruptSeed);
    ctx_.corruptedBlocks = result.first;
    ctx_.corruptedIndices = result.second;
}

// ==================================================================
// PdpAuditScenario — markStaleVersions
// ==================================================================

void PdpAuditScenario::markStaleVersions(std::size_t staleCount)
{
    if (staleCount == 0) return;
    if (ctx_.strategyKind != AuditCore::StrategyKind::Dynamic) {
        throw std::logic_error(
            "PdpAuditScenario::markStaleVersions: only valid for dynamic PDP strategies");
    }
    if (!ctx_.stateStore) {
        throw std::logic_error(
            "PdpAuditScenario::markStaleVersions: StateStore not initialized");
    }

    const std::size_t blockCount = ctx_.originalBlocks->availableBlockCount();
    const std::size_t actualStale = std::min(staleCount, blockCount);

    // Select random block indices to mark as stale
    std::vector<std::size_t> indices(blockCount);
    std::iota(indices.begin(), indices.end(), 0);

    std::uint64_t staleSeed = config_.usePseudoRandom ? config_.seed + 3 : 99;
    std::mt19937 gen(static_cast<std::mt19937::result_type>(staleSeed));
    std::shuffle(indices.begin(), indices.end(), gen);

    ctx_.staleIndices.assign(indices.begin(), indices.begin() + actualStale);

    // For each stale block, increment the version in the StateStore
    // This creates a version mismatch: the block data has version V,
    // but the StateStore now records version V+1
    // NOTE: stateStore API uses 1-based blockIndex; idx is 0-based
    for (auto idx : ctx_.staleIndices) {
        const std::size_t blockIndex = idx + 1;
        auto currentMeta = ctx_.stateStore->getBlockMetadata(ctx_.fileId, blockIndex);
        // Bump metadata in-place: increments version and refreshes timestamp
        ctx_.stateStore->modifyBlock(ctx_.fileId, blockIndex);
    }
}

// ==================================================================
// PdpAuditScenario — prepareCorruption
// ==================================================================

void PdpAuditScenario::prepareCorruption(std::size_t t)
{
    if (ctx_.strategyKind == AuditCore::StrategyKind::Dynamic) {
        markStaleVersions(t);
    } else {
        corruptBlocks(t);
    }
}

// ==================================================================
// PdpAuditScenario — prepare (virtual: pre-iteration setup)
// ==================================================================

void PdpAuditScenario::prepare(const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const PdpAuditConfig&>(config);
    if (cfg.corruptedBlocks > 0) {
        prepareCorruption(cfg.corruptedBlocks);
    }
}

// ==================================================================
// PdpAuditScenario — runIteration
// ==================================================================

bool PdpAuditScenario::runIteration()
{
    // Create a fresh operation context for this iteration
    // (reuse engine, keys, and tags from setup)
    AuditCore::AuditOperationContext iterCtx;

    // Copy key/tag state from the setup context into the iteration context
    iterCtx.initializeAlgorithmResult = ctx_.opCtx->initializeAlgorithmResult;
    iterCtx.generateKeysResult = ctx_.opCtx->generateKeysResult;
    iterCtx.generateTagsResult = ctx_.opCtx->generateTagsResult;

    // Step 1: Generate challenges — sample r blocks
    // For dynamic strategies, use stateStore's actual block count after
    // maintenance ops (inserts/deletes may have changed it). For static
    // strategies, use the original block source count.
    ::Json::Value chalJson;
    chalJson["fileId"]         = ctx_.fileId;
    chalJson["challengeCount"]  = static_cast<::Json::UInt64>(config_.sampleSize);
    chalJson["usePseudoRandom"] = false;  // True random for realistic benchmark
    if (ctx_.strategyKind == AuditCore::StrategyKind::Dynamic && ctx_.stateStore) {
        chalJson["blockCount"] = static_cast<::Json::UInt64>(
            ctx_.stateStore->getBlockCount(ctx_.fileId));
    } else {
        chalJson["blockCount"] = static_cast<::Json::UInt64>(
            ctx_.corruptedBlocks->availableBlockCount());
    }
    lastTimings_.genChallengesMs = measureMs([&]() {
        ctx_.engine->generateChallenges(jsonInput(chalJson), iterCtx);
    });

    // Step 2: Generate proofs using corrupted blocks + original tags
    auto proofsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
    proofsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(ctx_.corruptedBlocks));
    proofsDataMap->emplace("tags", AuditMsg::TagsPtr(ctx_.tags));
    lastTimings_.genProofsMs = measureMs([&]() {
        ctx_.engine->generateProofs(AuditMsg::RawInput(proofsDataMap), iterCtx);
    });

    // Step 3: Verify proofs
    ::Json::Value verifyJson;
    verifyJson["fileId"] = ctx_.fileId;
    verifyJson["userId"] = ctx_.userId;
    lastTimings_.verifyProofsMs = measureMs([&]() {
        ctx_.engine->verifyProofs(jsonInput(verifyJson), iterCtx);
    });

    // Step 4: Check result — detection means verifyProofs returned !ok
    lastDetected_ = !iterCtx.verifyProofsResult->ok;

    // Step 5: Record message sizes from the iteration context
    // Use serialization to measure actual wire sizes
    if (iterCtx.generateChallengesResult &&
        iterCtx.generateChallengesResult->challenges) {
        auto serialized = iterCtx.generateChallengesResult->challenges->serialize();
        lastMessageSizes_.challengeBytes = serialized.size();
    }
    if (iterCtx.generateProofsResult &&
        iterCtx.generateProofsResult->proves) {
        auto serialized = iterCtx.generateProofsResult->proves->serialize();
        lastMessageSizes_.proofBytes = serialized.size();
    }
    // Verify request size: challenge + proof + metadata
    lastMessageSizes_.verifyRequestBytes =
        lastMessageSizes_.challengeBytes + lastMessageSizes_.proofBytes;

    return lastDetected_;
}

// ==================================================================
// PdpAuditScenario — getSetupTimings
// ==================================================================

StageTimings PdpAuditScenario::getSetupTimings() const
{
    return ctx_.setupTimings;
}

// ==================================================================
// PdpAuditScenario — getLastTimings
// ==================================================================

StageTimings PdpAuditScenario::getLastTimings() const
{
    return lastTimings_;
}

// ==================================================================
// PdpAuditScenario — getLastMessageSizes
// ==================================================================

MessageSizes PdpAuditScenario::getLastMessageSizes() const
{
    return lastMessageSizes_;
}

// ==================================================================
// PdpAuditScenario — recordIteration (virtual: PDP outcome)
// ==================================================================

void PdpAuditScenario::recordIteration(MetricsCollector& collector)
{
    collector.recordOutcome(lastDetected_, "");
}

// ==================================================================
// PdpAuditScenario — computeResult (virtual: PdpAuditResult)
// ==================================================================

std::unique_ptr<BenchmarkResult> PdpAuditScenario::computeResult(
    const MetricsCollector& collector, const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const PdpAuditConfig&>(config);
    auto result = std::make_unique<PdpAuditResult>();
    collector.fillPdpResult(*result, cfg);
    return result;
}

// ==================================================================
// PdpAuditScenario — teardown
// ==================================================================

void PdpAuditScenario::teardown()
{
    ctx_.opCtx.reset();
    ctx_.engine.reset();
    ctx_.originalBlocks.reset();
    ctx_.corruptedBlocks.reset();
    ctx_.tags.reset();
    ctx_.corruptedIndices.clear();
    ctx_.staleIndices.clear();
    ctx_.stateStore.reset();
    ctx_.userId.clear();
    ctx_.fileId.clear();

    lastDetected_ = false;
    lastTimings_ = StageTimings{};
    lastMessageSizes_ = MessageSizes{};
}

// ==================================================================
// PdpAuditScenario — makeBlockSource (private, static)
// ==================================================================

AuditData::AuditBlockSourcePtr PdpAuditScenario::makeBlockSource(
    std::size_t totalBlocks, std::size_t blockSize, std::uint64_t seed)
{
    // Generate deterministic random data for each block
    std::mt19937 gen(static_cast<std::mt19937::result_type>(seed));
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::vector<std::uint8_t>> blocks;
    blocks.reserve(totalBlocks);

    for (std::size_t i = 0; i < totalBlocks; ++i) {
        std::vector<std::uint8_t> block(blockSize);
        for (std::size_t j = 0; j < blockSize; ++j) {
            block[j] = static_cast<std::uint8_t>(dist(gen));
        }
        blocks.push_back(std::move(block));
    }

    return std::make_shared<AuditData::MemoryAuditBlockSource>(
        std::move(blocks), blockSize, 0);
}

// ==================================================================
// PdpAuditScenario — corruptBlockSource (private, static)
// ==================================================================

std::pair<AuditData::AuditBlockSourcePtr, std::vector<std::size_t>>
PdpAuditScenario::corruptBlockSource(
    const AuditData::AuditBlockSourcePtr& original,
    std::size_t t, std::uint64_t seed)
{
    const std::size_t blockCount = original->availableBlockCount();
    const std::size_t blockSize = original->blockSize();
    const std::size_t actualT = std::min(t, blockCount);

    // Read all blocks from the original source
    std::vector<std::vector<std::uint8_t>> blocks;
    blocks.reserve(blockCount);
    for (std::size_t i = 0; i < blockCount; ++i) {
        blocks.push_back(original->block(i));
    }

    // Select t random block indices to corrupt
    std::vector<std::size_t> indices(blockCount);
    std::iota(indices.begin(), indices.end(), 0);

    std::mt19937 gen(static_cast<std::mt19937::result_type>(seed));
    std::shuffle(indices.begin(), indices.end(), gen);

    std::vector<std::size_t> corruptedIndices(indices.begin(), indices.begin() + actualT);

    // Corrupt each selected block by flipping the first byte
    for (auto idx : corruptedIndices) {
        if (!blocks[idx].empty()) {
            blocks[idx][0] ^= 0x01;  // Flip lowest bit of first byte
        }
    }

    auto corruptedSource = std::make_shared<AuditData::MemoryAuditBlockSource>(
        std::move(blocks), blockSize, original->globalBlockStartIndex());

    return {corruptedSource, corruptedIndices};
}

} // namespace CAMatrix::Audit::Benchmark
