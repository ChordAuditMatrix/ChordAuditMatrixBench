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
 * @file identity_verify_scenario.cpp
 * @brief Identity verification benchmark scenario implementation
 * @details Implements the setup/runIteration/teardown lifecycle for identity
 *          verification benchmarking. Generates labeled test samples containing
 *          legitimate signatures and various forgery types, then measures
 *          verification accuracy across iterations. Online algorithms
 *          (OnlineIdentitySigningAlgorithm tier) additionally generate
 *          session-coordinated aggregate samples: n = numUsers signers under
 *          one shared session string, aggregated per iteration (aggregateMs /
 *          aggregateSignatureBytes) and verified; tampered aggregates are
 *          rejected, cross-session mixing and duplicate signers are counted
 *          as rejected aggregations.
 * @author Dylan Liu
 * @version 2.1.0
 * @date 2026-08-25
 */

#include <ChordAuditMatrixBench/identity_verify_scenario.h>

// ── Framework ──
#include <ChordAuditMatrixBench/benchmark_types.h>

// ── Identity manager ──
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_manager.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_request.h"
#include "ChordAuditMatrixLib/interfaces/identity/online_identity_signing_algorithm.h"

// ── AuditDataMap for algorithm input ──
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

namespace {

/**
 * @brief Measure execution time of a callable in milliseconds
 * @tparam F Callable type
 * @param f Callable to measure
 * @return Execution time in milliseconds
 */
template <typename F>
double measureMs(F&& f)
{
    auto t0 = std::chrono::steady_clock::now();
    std::forward<F>(f)();
    auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

/**
 * @brief Read a little-endian uint32 from a byte buffer
 * @param p [IN] Byte buffer
 * @param o [IN] Byte offset (requires o + 4 <= available bytes)
 * @return Little-endian uint32 value
 */
std::uint32_t onaReadU32Le(const std::uint8_t* p, std::size_t o)
{
    return static_cast<std::uint32_t>(p[o])
        | (static_cast<std::uint32_t>(p[o + 1]) << 8)
        | (static_cast<std::uint32_t>(p[o + 2]) << 16)
        | (static_cast<std::uint32_t>(p[o + 3]) << 24);
}

/**
 * @brief Remove one signer entry from a serialized ONA aggregate record
 * @details ONA layout (在线多重签名实现文档.md §5.2):
 *          magic 'O','N','A',0x01 | wLen(4B LE) | w | n(4B LE)
 *          | n × (IDLen(4B LE), ID, mLen(4B LE), m) | S(96B) | T(192B).
 *          Rebuilds a well-formed record with the middle signer entry
 *          removed and n decremented (the roster has one fewer signer).
 * @param aggregate [IN] Serialized ONA aggregate signature
 * @return Rebuilt aggregate without one signer entry, or std::nullopt if
 *         the record does not parse per the serialization spec
 */
std::optional<CAMatrix::Crypto::CryptoArray> removeOneOnaEntry(
    const CAMatrix::Crypto::CryptoArray& aggregate)
{
    const auto* p = aggregate.data();
    const std::size_t size = aggregate.size();
    if (size < 4 + 4 + 4 + 96 + 192) {
        return std::nullopt;
    }
    if (p[0] != 'O' || p[1] != 'N' || p[2] != 'A' || p[3] != 0x01) {
        return std::nullopt;
    }
    std::size_t off = 4;
    const std::uint32_t wLen = onaReadU32Le(p, off);
    off += 4;
    if (off + wLen > size) {
        return std::nullopt;
    }
    off += wLen;
    const std::uint32_t n = onaReadU32Le(p, off);
    off += 4;
    if (n == 0) {
        return std::nullopt;
    }
    std::vector<std::pair<std::size_t, std::size_t>> entries;
    entries.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::size_t start = off;
        if (off + 4 > size) {
            return std::nullopt;
        }
        const std::uint32_t idLen = onaReadU32Le(p, off);
        off += 4;
        if (off + idLen > size) {
            return std::nullopt;
        }
        off += idLen;
        if (off + 4 > size) {
            return std::nullopt;
        }
        const std::uint32_t mLen = onaReadU32Le(p, off);
        off += 4;
        if (off + mLen > size) {
            return std::nullopt;
        }
        off += mLen;
        entries.emplace_back(start, off);
    }
    // S (96 B) + T (192 B) tail
    if (off + 96 + 192 != size) {
        return std::nullopt;
    }

    const std::size_t removeIdx = n / 2;
    CAMatrix::Crypto::CryptoArray out;
    out.reserve(size - (entries[removeIdx].second - entries[removeIdx].first));
    // magic
    out.insert(out.end(), {'O', 'N', 'A', 0x01});
    // wLen (4 B) + w
    out.insert(out.end(), p + 4, p + 8 + wLen);
    // n - 1 (little-endian)
    const std::uint32_t newN = n - 1;
    out.push_back(static_cast<std::uint8_t>(newN & 0xFF));
    out.push_back(static_cast<std::uint8_t>((newN >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((newN >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((newN >> 24) & 0xFF));
    // remaining signer entries
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (i == removeIdx) {
            continue;
        }
        out.insert(out.end(), p + entries[i].first, p + entries[i].second);
    }
    // S + T tail
    out.insert(out.end(), p + off, p + size);
    return out;
}

/**
 * @brief Flip one byte inside the signature element (S) of an aggregate
 * @details The ONA tail is S (96 B) then T (192 B); flipping a byte inside
 *          S changes the aggregate signature element so the pairing
 *          verification must fail (doc §2.3 byte-flip tamper sample).
 * @param aggregate [IN/OUT] Aggregate signature bytes
 */
void flipAggregateSignatureByte(CAMatrix::Crypto::CryptoArray& aggregate)
{
    if (aggregate.empty()) {
        return;
    }
    const std::size_t tail = (aggregate.size() >= 288) ? aggregate.size() - 288 : 0;
    std::size_t flipAt = tail + 48; // middle of S
    if (flipAt >= aggregate.size()) {
        flipAt = aggregate.size() - 1;
    }
    aggregate[flipAt] ^= 0x01;
}

} // anonymous namespace

// ==================================================================
// Construction
// ==================================================================

IdentityVerifyScenario::IdentityVerifyScenario(
    const std::string& algorithmType,
    std::shared_ptr<CAMatrix::Identity::Core::IdentityAlgorithmManager> manager)
    : algorithmType_(algorithmType)
    , manager_(std::move(manager))
    , rng_(std::random_device{}())
{
    if (!manager_) {
        throw std::invalid_argument("IdentityVerifyScenario: manager must not be null");
    }
}

// ==================================================================
// setup()
// ==================================================================

void IdentityVerifyScenario::setup(const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const IdentityConfig&>(config);
    config_ = cfg;

    // Seed the RNG if pseudo-random mode is requested
    if (cfg.usePseudoRandom) {
        rng_.seed(cfg.seed);
    }

    // ── Step 1: Use injected manager ──
    ctx_.manager = manager_;

    // ── Step 2: Kind dispatch — online (session-coordinated) vs offline ──
    {
        auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
        auto onlineAlgo = std::dynamic_pointer_cast<
            CAMatrix::Identity::Core::OnlineIdentitySigningAlgorithm>(algo);
        isOnline_ = (onlineAlgo != nullptr);
        if (isOnline_) {
            onlineAlgo_ = std::move(onlineAlgo);
        }
        // Consistency check: dynamic_cast result and kind() must agree
        // (OnlineIdentitySigningAlgorithm finalizes kind() = Online).
        const bool kindOnline =
            (algo->kind() == CAMatrix::Identity::Core::IdentityAlgorithmKind::Online);
        if (isOnline_ != kindOnline) {
            spdlog::error("IdentityVerifyScenario: kind()/dynamic_cast mismatch for algorithm '{}' "
                          "(derived from Online tier: {}, kind() == Online: {})",
                          algorithmType_, isOnline_, kindOnline);
            throw std::runtime_error(
                "IdentityVerifyScenario: kind()/dynamic_cast mismatch — algorithm '" +
                algorithmType_ + "' violates the Online/Offline tier contract");
        }
    }

    // ── Step 3: Generate master key pair ──
    auto initMs = measureMs([&] {
        auto [pub, priv] = ctx_.manager->getIdentityAlgorithm(algorithmType_)->generateMasterKey();
        ctx_.masterPub = pub;
        ctx_.masterPriv = priv;
    });
    ctx_.setupTimings.initAlgoMs = initMs;

    // ── Step 4: Derive per-user key pairs ──
    auto genKeysMs = measureMs([&] {
        for (std::size_t i = 0; i < cfg.numUsers; ++i) {
            auto userId = "user-" + std::to_string(i);
            auto [uPub, uPriv] = ctx_.manager->getIdentityAlgorithm(algorithmType_)->deriveUserKey(
                *ctx_.masterPub, *ctx_.masterPriv, userId);
            ctx_.userKeys[userId] = {uPub, uPriv};
        }
    });
    ctx_.setupTimings.genKeysMs = genKeysMs;

    // ── Step 5: Generate labeled test samples (measure signing time) ──
    // Online: also generate the aggregate sample set (n = numUsers signers
    // per sample, one shared session string) — auto-on, no extra CLI flag.
    auto signMs = measureMs([&] {
        ctx_.testSamples = generateTestSamples(cfg);
        ctx_.aggregateSamples = generateAggregateSamples(cfg);
    });
    ctx_.setupTimings.signMs = signMs;
}

// ==================================================================
// runIteration()
// ==================================================================

bool IdentityVerifyScenario::runIteration()
{
    using AuditDataMap = CAMatrix::Audit::Messages::AuditDataMap;

    lastTA_ = lastFA_ = lastTR_ = lastFR_ = 0;
    lastRejectedAggregation_ = 0;
    double totalSignMs = 0;
    double totalVerifyMs = 0;
    std::size_t totalSignatureBytes = 0;
    std::size_t totalVerifyRequestBytes = 0;

    for (const auto& sample : ctx_.testSamples) {
        // ── Construct AuditDataMap for aggregateVerify ──
        AuditDataMap verifyInput;
        verifyInput.emplace("aggregateSignature", sample.signature);
        verifyInput.emplace("message", CAMatrix::Crypto::CryptoArray(sample.message.begin(), sample.message.end()));
        verifyInput.emplace("masterPub", ctx_.masterPub);

        // Build signers list: single signer
        std::vector<std::string> userIds = {sample.userId};
        auto it = ctx_.userKeys.find(sample.userId);
        std::vector<std::shared_ptr<
            CAMatrix::Identity::Core::AlgoUserPublicParams>> userPubKeys;
        if (it != ctx_.userKeys.end()) {
            userPubKeys.push_back(it->second.pub);
        }
        verifyInput.emplace("userIds", userIds);
        verifyInput.emplace("userPubKeys", userPubKeys);

        // ── Measure verification time ──
        bool accepted = false;
        auto verifyMs = measureMs([&] {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Verify, verifyInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::AggregateVerifyRequest>>(*variant);
            accepted = algo->aggregateVerify(*req);
        });
        totalVerifyMs += verifyMs;

        // ── Accumulate message sizes ──
        totalSignatureBytes += sample.signature.size();
        totalVerifyRequestBytes +=
            sample.signature.size() + sample.message.size() + sample.userId.size();

        // ── Count TP/FP/TN/FN ──
        if (sample.shouldAccept && accepted) {
            ++lastTA_;
        } else if (!sample.shouldAccept && accepted) {
            ++lastFA_;
        } else if (!sample.shouldAccept && !accepted) {
            ++lastTR_;
        } else {
            // shouldAccept && !accepted → FN
            ++lastFR_;
        }
    }

    // ── Online aggregate samples (n = numUsers signers, one shared session) ──
    double totalAggregateMs = 0;
    double totalAggregateVerifyMs = 0;
    std::size_t totalAggregateBytes = 0;
    std::size_t aggregateCount = 0;
    if (isOnline_ && !ctx_.aggregateSamples.empty()) {
        for (const auto& sample : ctx_.aggregateSamples) {
            // ── Aggregation rejection checks (cross-session / duplicate):
            //    never enter the TP/FP/TN/FN confusion matrix ──
            if (sample.tamperMode == AggregateTamperMode::CrossSession ||
                sample.tamperMode == AggregateTamperMode::DuplicateSigner) {
                bool aggregationRejected = false;
                try {
                    auto result = onlineAlgo_->aggregateSessionSignatures(
                        sample.signatures, sample.sessionString);
                    aggregationRejected = result.empty(); // empty result = failure
                } catch (const std::exception&) {
                    aggregationRejected = true;
                }
                if (aggregationRejected) {
                    ++lastRejectedAggregation_;
                }
                continue;
            }

            // ── Verify-path sample: aggregate (timed) → tamper → aggregateVerify ──
            CAMatrix::Crypto::CryptoArray aggregate;
            bool aggregateOk = true;
            try {
                const double aggMs = measureMs([&] {
                    aggregate = onlineAlgo_->aggregateSessionSignatures(
                        sample.signatures, sample.sessionString);
                });
                totalAggregateMs += aggMs;
            } catch (const std::exception&) {
                aggregateOk = false;
            }

            if (!aggregateOk) {
                // Aggregation failed on a verify-path sample → outcome is reject
                if (sample.tamperMode == AggregateTamperMode::None) {
                    ++lastFR_; // legal sample wrongly rejected
                } else {
                    ++lastTR_; // tampered sample rejected as expected
                }
                continue;
            }

            ++aggregateCount;
            totalAggregateBytes += aggregate.size();

            // ── Build the verifier's signer list ──
            std::vector<std::string> verifyUserIds = sample.userIds;
            std::vector<std::shared_ptr<
                CAMatrix::Identity::Core::AlgoUserPublicParams>> verifyPubKeys;
            verifyPubKeys.reserve(sample.userIds.size());
            for (const auto& userId : sample.userIds) {
                auto keyIt = ctx_.userKeys.find(userId);
                if (keyIt == ctx_.userKeys.end()) {
                    aggregateOk = false;
                    break;
                }
                verifyPubKeys.push_back(keyIt->second.pub);
            }
            if (!aggregateOk) {
                if (sample.tamperMode == AggregateTamperMode::None) {
                    ++lastFR_;
                } else {
                    ++lastTR_;
                }
                continue;
            }

            // ── Apply the tamper construction ──
            bool shouldAccept = true;
            if (sample.tamperMode == AggregateTamperMode::FlipByte) {
                flipAggregateSignatureByte(aggregate);
                shouldAccept = false;
            } else if (sample.tamperMode == AggregateTamperMode::RemoveEntry) {
                auto stripped = removeOneOnaEntry(aggregate);
                if (stripped) {
                    aggregate = std::move(*stripped);
                }
                // Drop the same roster position from the verifier's signer list
                // (if the ONA parse failed, the roster/signer-list mismatch
                //  still makes verification reject).
                const std::size_t removeIdx = sample.userIds.size() / 2;
                verifyUserIds.erase(verifyUserIds.begin() + removeIdx);
                verifyPubKeys.erase(verifyPubKeys.begin() + removeIdx);
                shouldAccept = false;
            }

            // ── Verify the (possibly tampered) aggregate ──
            AuditDataMap verifyInput;
            verifyInput.emplace("aggregateSignature", aggregate);
            verifyInput.emplace("message", sample.messages.front());
            verifyInput.emplace("masterPub", ctx_.masterPub);
            verifyInput.emplace("userIds", verifyUserIds);
            verifyInput.emplace("userPubKeys", verifyPubKeys);

            bool accepted = false;
            const double verifyMs = measureMs([&] {
                auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
                auto variant = algo->createRequest(
                    CAMatrix::Identity::Core::IdentityOperation::Verify, verifyInput);
                auto req = std::get<std::shared_ptr<
                    CAMatrix::Identity::Core::AggregateVerifyRequest>>(*variant);
                accepted = algo->aggregateVerify(*req);
            });
            totalAggregateVerifyMs += verifyMs;

            if (shouldAccept && accepted) {
                ++lastTA_;
            } else if (!shouldAccept && accepted) {
                ++lastFA_;
            } else if (!shouldAccept && !accepted) {
                ++lastTR_;
            } else {
                // shouldAccept && !accepted → FN
                ++lastFR_;
            }
        }
    }

    // ── Compute accuracy rate ──
    std::size_t total = lastTA_ + lastFA_ + lastTR_ + lastFR_;
    lastAccuracyRate_ = (total > 0)
        ? static_cast<double>(lastTA_ + lastTR_) / static_cast<double>(total)
        : 0.0;

    // ── Record average timings per sample ──
    std::size_t sampleCount = ctx_.testSamples.size();
    std::size_t totalSampleCount = sampleCount + ctx_.aggregateSamples.size();
    lastTimings_ = StageTimings{};
    lastTimings_.signMs = (totalSampleCount > 0) ? ctx_.setupTimings.signMs / totalSampleCount : 0;
    lastTimings_.verifyMs = (sampleCount > 0) ? totalVerifyMs / sampleCount : 0;
    lastTimings_.aggregateVerifyMs =
        (sampleCount + aggregateCount > 0)
            ? (totalVerifyMs + totalAggregateVerifyMs)
                  / (sampleCount + aggregateCount)
            : 0;
    lastTimings_.aggregateMs =
        (aggregateCount > 0) ? totalAggregateMs / aggregateCount : 0;

    // ── Record message sizes (average per sample) ──
    lastMessageSizes_ = MessageSizes{};
    lastMessageSizes_.signatureBytes =
        (sampleCount > 0) ? totalSignatureBytes / sampleCount : 0;
    lastMessageSizes_.verifyRequestBytes =
        (sampleCount > 0) ? totalVerifyRequestBytes / sampleCount : 0;
    lastMessageSizes_.aggregateSignatureBytes =
        (aggregateCount > 0) ? totalAggregateBytes / aggregateCount : 0;

    return true;
}

// ==================================================================
// Accessors
// ==================================================================

StageTimings IdentityVerifyScenario::getSetupTimings() const
{
    return ctx_.setupTimings;
}

StageTimings IdentityVerifyScenario::getLastTimings() const
{
    return lastTimings_;
}

MessageSizes IdentityVerifyScenario::getLastMessageSizes() const
{
    return lastMessageSizes_;
}

// ==================================================================
// teardown()
// ==================================================================

void IdentityVerifyScenario::teardown()
{
    ctx_ = IdentityScenarioContext{};
    lastAccuracyRate_ = 0;
    lastTA_ = lastFA_ = lastTR_ = lastFR_ = 0;
    lastRejectedAggregation_ = 0;
    lastTimings_ = StageTimings{};
    lastMessageSizes_ = MessageSizes{};
}

// ==================================================================
// recordIteration() — record per-sample TP/FP/TN/FN from last iteration
// ==================================================================

void IdentityVerifyScenario::recordIteration(MetricsCollector& collector)
{
    // TP: accepted && shouldAccept
    for (std::size_t tp = 0; tp < lastTA_; ++tp)
        collector.recordIdentityOutcome(true, true);
    // FP: accepted && !shouldAccept
    for (std::size_t fp = 0; fp < lastFA_; ++fp)
        collector.recordIdentityOutcome(true, false);
    // TN: !accepted && !shouldAccept
    for (std::size_t tn = 0; tn < lastTR_; ++tn)
        collector.recordIdentityOutcome(false, false);
    // FN: !accepted && shouldAccept
    for (std::size_t fn = 0; fn < lastFR_; ++fn)
        collector.recordIdentityOutcome(false, true);
    // Online aggregation rejections (cross-session / duplicate signer):
    // counted separately, never part of the confusion matrix
    collector.recordRejectedAggregation(lastRejectedAggregation_);
}

// ==================================================================
// computeResult() — returns IdentityResult
// ==================================================================

std::unique_ptr<BenchmarkResult> IdentityVerifyScenario::computeResult(
    const MetricsCollector& collector, const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const IdentityConfig&>(config);
    auto result = std::make_unique<IdentityResult>();
    collector.fillIdentityResult(*result, cfg);
    result->algorithmKind = isOnline_ ? "Online" : "Offline";
    result->aggregateSigners = (isOnline_ && cfg.numUsers >= 2) ? cfg.numUsers : 0;
    return result;
}

// ==================================================================
// generateTestSamples()
// ==================================================================

std::vector<IdentitySampleLabel>
IdentityVerifyScenario::generateTestSamples(const IdentityConfig& config)
{
    using AuditDataMap = CAMatrix::Audit::Messages::AuditDataMap;

    std::vector<IdentitySampleLabel> samples;
    auto& neg = config.negativeSamples;
    double positiveRatio =
        1.0 - neg.forgeryRatio - neg.tamperedRatio - neg.impersonationRatio;
    std::size_t totalSamples = config.samplesPerIteration;

    // ── 1. Positive samples: legitimate signatures ──
    std::size_t posCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * positiveRatio);
    for (std::size_t i = 0; i < posCount; ++i) {
        auto userId = randomUserId(config.numUsers);
        auto message = randomMessage();
        auto it = ctx_.userKeys.find(userId);
        if (it == ctx_.userKeys.end()) {
            continue; // skip if user not found (shouldn't happen)
        }

        // Sign with the correct user's private key
        AuditDataMap signInput;
        signInput.emplace("message", CAMatrix::Crypto::CryptoArray(message.begin(), message.end()));
        signInput.emplace("userId", userId);
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", it->second.priv);
        if (isOnline_) {
            signInput.emplace("sessionString", makeBenchSessionString());
        }

        CAMatrix::Crypto::CryptoArray signature;
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            auto sigRaw = algo->sign(*req);
            signature = std::move(sigRaw);
        } catch (...) {
            continue; // skip on signing failure
        }

        samples.push_back({message, std::move(signature), userId, true});
    }

    // ── 2. Forgery samples: signed by a different user ──
    std::size_t forgeryCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.forgeryRatio);
    for (std::size_t i = 0; i < forgeryCount; ++i) {
        auto realUser = randomUserId(config.numUsers);
        auto otherUser = randomOtherUserId(config.numUsers, realUser);
        auto message = randomMessage();
        auto it = ctx_.userKeys.find(otherUser);
        if (it == ctx_.userKeys.end()) {
            continue;
        }

        // Sign with other user's private key, but claim realUser's identity
        AuditDataMap signInput;
        signInput.emplace("message", CAMatrix::Crypto::CryptoArray(message.begin(), message.end()));
        signInput.emplace("userId", otherUser);
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", it->second.priv);
        if (isOnline_) {
            signInput.emplace("sessionString", makeBenchSessionString());
        }

        CAMatrix::Crypto::CryptoArray signature;
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            auto sigRaw = algo->sign(*req);
            signature = std::move(sigRaw);
        } catch (...) {
            continue;
        }

        // The signature is valid for otherUser, but we claim it's from realUser
        samples.push_back({message, std::move(signature), realUser, false});
    }

    // ── 3. Tampered message samples: legitimate signature + modified message ──
    std::size_t tamperedCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.tamperedRatio);
    for (std::size_t i = 0; i < tamperedCount; ++i) {
        auto userId = randomUserId(config.numUsers);
        auto originalMsg = randomMessage();
        auto tamperedMsg = tamperMessage(originalMsg);
        auto it = ctx_.userKeys.find(userId);
        if (it == ctx_.userKeys.end()) {
            continue;
        }

        // Sign the original message
        AuditDataMap signInput;
        signInput.emplace("message", CAMatrix::Crypto::CryptoArray(originalMsg.begin(), originalMsg.end()));
        signInput.emplace("userId", userId);
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", it->second.priv);
        if (isOnline_) {
            signInput.emplace("sessionString", makeBenchSessionString());
        }

        CAMatrix::Crypto::CryptoArray signature;
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            auto sigRaw = algo->sign(*req);
            signature = std::move(sigRaw);
        } catch (...) {
            continue;
        }

        // Verify with tampered message — should fail
        samples.push_back({tamperedMsg, std::move(signature), userId, false});
    }

    // ── 4. Impersonation samples: legitimate signature but wrong userId ──
    std::size_t impCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.impersonationRatio);
    for (std::size_t i = 0; i < impCount; ++i) {
        auto realUser = randomUserId(config.numUsers);
        auto fakeUser = randomOtherUserId(config.numUsers, realUser);
        auto message = randomMessage();
        auto itFake = ctx_.userKeys.find(fakeUser);
        if (itFake == ctx_.userKeys.end()) {
            continue;
        }

        // Sign with fakeUser's key
        AuditDataMap signInput;
        signInput.emplace("message", CAMatrix::Crypto::CryptoArray(message.begin(), message.end()));
        signInput.emplace("userId", fakeUser);
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", itFake->second.priv);
        if (isOnline_) {
            signInput.emplace("sessionString", makeBenchSessionString());
        }

        CAMatrix::Crypto::CryptoArray signature;
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            auto sigRaw = algo->sign(*req);
            signature = std::move(sigRaw);
        } catch (...) {
            continue;
        }

        // Claim this is from realUser — signature won't match
        samples.push_back({message, std::move(signature), realUser, false});
    }

    // ── 5. Shuffle samples to avoid ordering bias ──
    std::shuffle(samples.begin(), samples.end(), rng_);

    return samples;
}

// ==================================================================
// generateAggregateSamples() — online aggregate samples (n = numUsers)
// ==================================================================

std::vector<IdentityAggregateSample>
IdentityVerifyScenario::generateAggregateSamples(const IdentityConfig& config)
{
    using AuditDataMap = CAMatrix::Audit::Messages::AuditDataMap;

    std::vector<IdentityAggregateSample> samples;
    // Aggregate scenario is auto-on: online algorithm AND numUsers >= 2
    // (reuses --num-users; no new CLI parameter).
    if (!isOnline_ || config.numUsers < 2) {
        return samples;
    }
    const std::size_t n = config.numUsers;

    // Sample counts per kind. Legal and verify-path tampered counts are EQUAL
    // (doc §2.3 口径) so the aggregate accuracy contribution is unbiased.
    const std::size_t legalCount = 4;
    const std::size_t flipByteCount = 2;
    const std::size_t removeEntryCount = 2; // total verify-path tampered = 4 == legalCount
    const std::size_t crossSessionCount = 1;
    const std::size_t duplicateCount = 1;

    // Sign one message for a user under a session string
    auto signFor = [&](const std::string& userId,
                       const std::string& message,
                       const std::string& sessionString)
        -> CAMatrix::Crypto::CryptoArray {
        auto it = ctx_.userKeys.find(userId);
        if (it == ctx_.userKeys.end()) {
            return {};
        }
        AuditDataMap signInput;
        signInput.emplace("message",
            CAMatrix::Crypto::CryptoArray(message.begin(), message.end()));
        signInput.emplace("userId", userId);
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", it->second.priv);
        signInput.emplace("sessionString", sessionString);
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            return algo->sign(*req);
        } catch (...) {
            return {};
        }
    };

    // Fill n signers, each signing a distinct message under one session
    auto fillSample = [&](IdentityAggregateSample& sample) -> bool {
        for (std::size_t i = 0; i < n; ++i) {
            auto userId = "user-" + std::to_string(i);
            auto message = randomMessage();
            auto sig = signFor(userId, message, sample.sessionString);
            if (sig.empty()) {
                return false;
            }
            sample.userIds.push_back(std::move(userId));
            sample.messages.emplace_back(message.begin(), message.end());
            sample.signatures.push_back(std::move(sig));
        }
        return true;
    };

    // ── 1. Legal aggregate samples (expect accept / TP) ──
    for (std::size_t k = 0; k < legalCount; ++k) {
        IdentityAggregateSample sample;
        sample.tamperMode = AggregateTamperMode::None;
        sample.sessionString = makeBenchSessionString();
        if (fillSample(sample)) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 2. Tampered: one byte flipped inside the aggregate signature (expect reject / TN) ──
    for (std::size_t k = 0; k < flipByteCount; ++k) {
        IdentityAggregateSample sample;
        sample.tamperMode = AggregateTamperMode::FlipByte;
        sample.sessionString = makeBenchSessionString();
        if (fillSample(sample)) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 3. Tampered: one signer entry removed from the ONA roster (expect reject / TN) ──
    for (std::size_t k = 0; k < removeEntryCount; ++k) {
        IdentityAggregateSample sample;
        sample.tamperMode = AggregateTamperMode::RemoveEntry;
        sample.sessionString = makeBenchSessionString();
        if (fillSample(sample)) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 4. Cross-session mixing: n-1 signers under session 1, last under
    //       session 2 → aggregateSessionSignatures must reject (counted as
    //       rejectedAggregation, never a TP/FP) ──
    for (std::size_t k = 0; k < crossSessionCount; ++k) {
        IdentityAggregateSample sample;
        sample.tamperMode = AggregateTamperMode::CrossSession;
        sample.sessionString = makeBenchSessionString();
        sample.sessionString2 = makeBenchSessionString();
        bool ok = true;
        for (std::size_t i = 0; i + 1 < n; ++i) {
            auto userId = "user-" + std::to_string(i);
            auto message = randomMessage();
            auto sig = signFor(userId, message, sample.sessionString);
            if (sig.empty()) {
                ok = false;
                break;
            }
            sample.userIds.push_back(std::move(userId));
            sample.messages.emplace_back(message.begin(), message.end());
            sample.signatures.push_back(std::move(sig));
        }
        if (ok) {
            auto userId = "user-" + std::to_string(n - 1);
            auto message = randomMessage();
            auto sig = signFor(userId, message, sample.sessionString2);
            if (sig.empty()) {
                ok = false;
            } else {
                sample.userIds.push_back(std::move(userId));
                sample.messages.emplace_back(message.begin(), message.end());
                sample.signatures.push_back(std::move(sig));
            }
        }
        if (ok) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 5. Duplicate signer: same (session, userId) signs twice → the
    //       aggregation must reject (counted as rejectedAggregation) ──
    for (std::size_t k = 0; k < duplicateCount; ++k) {
        IdentityAggregateSample sample;
        sample.tamperMode = AggregateTamperMode::DuplicateSigner;
        sample.sessionString = makeBenchSessionString();
        bool ok = true;
        // user-0 signs two distinct messages under the same session
        for (std::size_t dup = 0; dup < 2 && ok; ++dup) {
            auto userId = "user-0";
            auto message = randomMessage();
            auto sig = signFor(userId, message, sample.sessionString);
            if (sig.empty()) {
                ok = false;
                break;
            }
            sample.userIds.push_back(std::move(userId));
            sample.messages.emplace_back(message.begin(), message.end());
            sample.signatures.push_back(std::move(sig));
        }
        // users 1..n-2 sign once → n signatures total with one duplicate
        for (std::size_t i = 1; i + 1 < n && ok; ++i) {
            auto userId = "user-" + std::to_string(i);
            auto message = randomMessage();
            auto sig = signFor(userId, message, sample.sessionString);
            if (sig.empty()) {
                ok = false;
                break;
            }
            sample.userIds.push_back(std::move(userId));
            sample.messages.emplace_back(message.begin(), message.end());
            sample.signatures.push_back(std::move(sig));
        }
        if (ok) {
            samples.push_back(std::move(sample));
        }
    }

    return samples;
}

// ==================================================================
// makeBenchSessionString() — internal session counter (NOT a CLI param)
// ==================================================================

std::string IdentityVerifyScenario::makeBenchSessionString()
{
    return onlineAlgo_->makeSessionString(
        "bench-" + std::to_string(sessionCounter_++), "IdentityVerify");
}

// ==================================================================
// Private helpers
// ==================================================================

std::string IdentityVerifyScenario::randomUserId(std::size_t numUsers)
{
    std::uniform_int_distribution<std::size_t> dist(0, numUsers - 1);
    return "user-" + std::to_string(dist(rng_));
}

std::string IdentityVerifyScenario::randomOtherUserId(
    std::size_t numUsers,
    const std::string& excludeId)
{
    if (numUsers <= 1) {
        return excludeId; // can't pick a different user with only 1 user
    }
    std::uniform_int_distribution<std::size_t> dist(0, numUsers - 2);
    std::size_t idx = dist(rng_);
    // Map to skip the excluded user
    auto excludedNum = std::stoull(excludeId.substr(5)); // "user-NNN"
    if (idx >= excludedNum) {
        ++idx;
    }
    return "user-" + std::to_string(idx);
}

std::string IdentityVerifyScenario::randomMessage()
{
    // Generate a random 32-byte hex string as the message
    static constexpr char hexChars[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string msg;
    msg.reserve(64);
    for (int i = 0; i < 64; ++i) {
        msg.push_back(hexChars[dist(rng_)]);
    }
    return msg;
}

std::string IdentityVerifyScenario::tamperMessage(const std::string& message)
{
    if (message.empty()) {
        return message;
    }
    std::string tampered = message;
    // Flip the last byte's lowest bit
    tampered.back() ^= 0x01;
    return tampered;
}

} // namespace CAMatrix::Audit::Benchmark
