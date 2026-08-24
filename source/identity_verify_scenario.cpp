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
 * @brief Sign a message with a user's private key → σᵢ (raw bytes)
 * @param userId User whose private key signs
 * @param message Message (CryptoArray) to sign
 * @param ctx Scenario context (manager + master key + user keys)
 * @param algorithmType Identity algorithm type
 * @return Raw signature bytes
 */
CAMatrix::Crypto::CryptoArray signForUser(
    const std::string& userId,
    const CAMatrix::Crypto::CryptoArray& message,
    const IdentityScenarioContext& ctx,
    const std::string& algorithmType,
    const std::string& sessionString = {})
{
    auto it = ctx.userKeys.find(userId);
    if (it == ctx.userKeys.end()) {
        throw std::invalid_argument("signForUser: unknown user " + userId);
    }

    CAMatrix::Audit::Messages::AuditDataMap signInput;
    signInput.emplace("message", message);
    signInput.emplace("userId", userId);
    signInput.emplace("masterPub", ctx.masterPub);
    signInput.emplace("userPriv", it->second.priv);
    if (!sessionString.empty()) {
        signInput.emplace("sessionString", sessionString);
    }

    auto algo = ctx.manager->getIdentityAlgorithm(algorithmType);
    auto variant = algo->createRequest(
        CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
    auto req = std::get<std::shared_ptr<
        CAMatrix::Identity::Core::SignRequest>>(*variant);
    return algo->sign(*req);
}

/**
 * @brief Fill a sample with numUsers legitimate signatures over the same message
 * @param sample Sample to fill
 * @param message Message (CryptoArray) all signers sign
 * @param ctx Scenario context
 * @param algorithmType Identity algorithm type
 * @param numUsers Number of signers (user-0 .. user-(numUsers-1))
 * @param sessionString Online session string (empty for offline)
 */
void fillLegitSigners(IdentitySampleLabel& sample,
                      const CAMatrix::Crypto::CryptoArray& message,
                      const IdentityScenarioContext& ctx,
                      const std::string& algorithmType,
                      std::size_t numUsers,
                      const std::string& sessionString = {})
{
    for (std::size_t j = 0; j < numUsers; ++j) {
        auto userId = "user-" + std::to_string(j);
        auto it = ctx.userKeys.find(userId);
        if (it == ctx.userKeys.end()) {
            continue;
        }

        sample.signatures.push_back(signForUser(userId, message, ctx, algorithmType, sessionString));
        sample.userIds.push_back(userId);
        sample.userPubKeys.push_back(it->second.pub);
    }
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
    auto signMs = measureMs([&] {
        ctx_.testSamples = generateTestSamples(cfg);
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
    double totalVerifyMs = 0;
    std::size_t totalSignatureBytes = 0;
    std::size_t totalVerifyRequestBytes = 0;
    std::size_t totalSignatureCount = 0;
    double totalAggregateMs = 0;
    std::size_t totalAggregateBytes = 0;
    std::size_t aggregateCount = 0;

    for (const auto& sample : ctx_.testSamples) {
        CAMatrix::Crypto::CryptoArray msgBytes(sample.message.begin(), sample.message.end());

        // ── 1. Aggregate individual signatures → Σ (tier-specific) ──
        CAMatrix::Crypto::CryptoArray aggSig;
        bool accepted = false;
        try {
            const double aggMs = measureMs([&] {
                if (isOnline_) {
                    aggSig = onlineAlgo_->aggregateSessionSignatures(
                        sample.signatures, sample.sessionString);
                } else {
                    AuditDataMap aggInput;
                    aggInput.emplace("message", msgBytes);
                    aggInput.emplace("signatures", sample.signatures);
                    aggInput.emplace("userIds", sample.userIds);
                    aggInput.emplace("userPubKeys", sample.userPubKeys);
                    aggInput.emplace("masterPub", ctx_.masterPub);
                    auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
                    auto aggVariant = algo->createRequest(
                        CAMatrix::Identity::Core::IdentityOperation::Aggregate, aggInput);
                    auto aggReq = std::get<std::shared_ptr<
                        CAMatrix::Identity::Core::AggregateRequest>>(*aggVariant);
                    aggSig = algo->aggregate(*aggReq);
                }
            });
            totalAggregateMs += aggMs;
        } catch (...) {
            // Aggregate failed → verification fails
            if (!sample.shouldAccept) ++lastTR_;
            else ++lastFR_;
            continue;
        }
        if (aggSig.empty()) {
            if (!sample.shouldAccept) ++lastTR_;
            else ++lastFR_;
            continue;
        }
        ++aggregateCount;
        totalAggregateBytes += aggSig.size();

        // ── 2. Aggregate-verify Σ against all signers ──
        AuditDataMap verifyInput;
        verifyInput.emplace("aggregateSignature", aggSig);
        verifyInput.emplace("message", msgBytes);
        verifyInput.emplace("masterPub", ctx_.masterPub);
        verifyInput.emplace("userIds", sample.userIds);
        verifyInput.emplace("userPubKeys", sample.userPubKeys);

        auto verifyMs = measureMs([&] {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Verify, verifyInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::AggregateVerifyRequest>>(*variant);
            accepted = algo->aggregateVerify(*req);
        });
        totalVerifyMs += verifyMs;

        // ── Accumulate message sizes (per-signature averages) ──
        for (std::size_t k = 0; k < sample.signatures.size(); ++k) {
            totalSignatureBytes += sample.signatures[k].size();
            totalVerifyRequestBytes +=
                sample.signatures[k].size() + sample.message.size() + sample.userIds[k].size();
        }
        totalSignatureCount += sample.signatures.size();

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

    std::size_t total = lastTA_ + lastFA_ + lastTR_ + lastFR_;
    lastAccuracyRate_ = (total > 0)
        ? static_cast<double>(lastTA_ + lastTR_) / static_cast<double>(total)
        : 0.0;

    // ── Record average timings per sample ──
    std::size_t sampleCount = ctx_.testSamples.size();
    lastTimings_ = StageTimings{};
    lastTimings_.signMs = (sampleCount > 0) ? ctx_.setupTimings.signMs / sampleCount : 0;
    lastTimings_.verifyMs = (sampleCount > 0) ? totalVerifyMs / sampleCount : 0;
    lastTimings_.aggregateVerifyMs =
        (sampleCount > 0) ? totalVerifyMs / sampleCount : 0;
    lastTimings_.aggregateMs =
        (aggregateCount > 0) ? totalAggregateMs / aggregateCount : 0;

    // ── Record message sizes (average per individual signature) ──
    lastMessageSizes_ = MessageSizes{};
    lastMessageSizes_.signatureBytes =
        (totalSignatureCount > 0) ? totalSignatureBytes / totalSignatureCount : 0;
    lastMessageSizes_.verifyRequestBytes =
        (totalSignatureCount > 0) ? totalVerifyRequestBytes / totalSignatureCount : 0;
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

    // ── 1. Positive samples: numUsers users sign the same message → aggregate ──
    std::size_t posCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * positiveRatio);
    for (std::size_t i = 0; i < posCount; ++i) {
        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = true;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        fillLegitSigners(sample, msgBytes, ctx_, algorithmType_, config.numUsers,
                         sample.sessionString);
        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 2. Forgery samples: aggregate with one forged signature → reject ──
    std::size_t forgeryCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.forgeryRatio);

    // External attacker key pair — NOT registered in the user pool.
    // Derived once per generateTestSamples call (SM9 key derivation is
    // expensive); the forged signature must fail against the claimed
    // victim's public key.
    std::shared_ptr<CAMatrix::Identity::Core::AlgoUserPrivateParams> forgerPriv;
    if (forgeryCount > 0 && config.numUsers >= 2) {
        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto forgerKeys = algo->deriveUserKey(
                *ctx_.masterPub, *ctx_.masterPriv, "forger-external");
            forgerPriv = forgerKeys.second;
        } catch (...) {
            // Key derivation failed → skip all forgery samples
            forgeryCount = 0;
        }
    }

    for (std::size_t i = 0; i < forgeryCount; ++i) {
        if (config.numUsers < 2) {
            continue;
        }

        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        // Legitimate part: user-0 .. user-(N-2) sign the same message
        for (std::size_t j = 0; j < config.numUsers - 1; ++j) {
            auto userId = "user-" + std::to_string(j);
            auto it = ctx_.userKeys.find(userId);
            if (it == ctx_.userKeys.end()) {
                continue;
            }

            sample.signatures.push_back(signForUser(
                userId, msgBytes, ctx_, algorithmType_, sample.sessionString));
            sample.userIds.push_back(userId);
            sample.userPubKeys.push_back(it->second.pub);
        }

        // Forgery part: forge a signature with an UNREGISTERED key pair
        // (external attacker — not in the user pool), claiming to be
        // user-(N-1) → aggregate verification must reject.
        auto victimId = "user-" + std::to_string(config.numUsers - 1);
        auto victimKeyIt = ctx_.userKeys.find(victimId);
        if (victimKeyIt == ctx_.userKeys.end()) {
            continue;
        }

        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);

            AuditDataMap signInput;
            signInput.emplace("message", msgBytes);
            signInput.emplace("userId", "forger-external");
            signInput.emplace("masterPub", ctx_.masterPub);
            signInput.emplace("userPriv", forgerPriv);
            if (!sample.sessionString.empty()) {
                signInput.emplace("sessionString", sample.sessionString);
            }

            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            sample.signatures.push_back(algo->sign(*req));
            sample.userIds.push_back(victimId);   // claims to be user-(N-1)
            sample.userPubKeys.push_back(victimKeyIt->second.pub);
        } catch (...) {
            continue;
        }

        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 3. Tampered message samples: signatures over the original message,
    //    verification uses the tampered message → aggregate must reject ──
    std::size_t tamperedCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.tamperedRatio);
    for (std::size_t i = 0; i < tamperedCount; ++i) {
        auto originalMsg = randomMessage();
        auto tamperedMsg = tamperMessage(originalMsg);
        CAMatrix::Crypto::CryptoArray originalBytes(originalMsg.begin(), originalMsg.end());

        IdentitySampleLabel sample;
        sample.message = tamperedMsg;   // verification uses the tampered message
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        fillLegitSigners(sample, originalBytes, ctx_, algorithmType_, config.numUsers,
                         sample.sessionString);
        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 4. Impersonation samples: one signer claims another identity → reject ──
    std::size_t impCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.impersonationRatio);
    for (std::size_t i = 0; i < impCount; ++i) {
        if (config.numUsers < 2) {
            continue;
        }

        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        // Legitimate part: user-0 .. user-(N-2)
        for (std::size_t j = 0; j < config.numUsers - 1; ++j) {
            auto userId = "user-" + std::to_string(j);
            auto it = ctx_.userKeys.find(userId);
            if (it == ctx_.userKeys.end()) {
                continue;
            }

            sample.signatures.push_back(signForUser(
                userId, msgBytes, ctx_, algorithmType_, sample.sessionString));
            sample.userIds.push_back(userId);
            sample.userPubKeys.push_back(it->second.pub);
        }

        // Impersonation part: signed with user-0's key, claims to be user-(N-1)
        auto victimId = "user-" + std::to_string(config.numUsers - 1);
        auto victimKeyIt = ctx_.userKeys.find(victimId);
        auto impersonatorKeyIt = ctx_.userKeys.find("user-0");
        if (victimKeyIt == ctx_.userKeys.end() || impersonatorKeyIt == ctx_.userKeys.end()) {
            continue;
        }

        AuditDataMap signInput;
        signInput.emplace("message", msgBytes);
        signInput.emplace("userId", "user-0");
        signInput.emplace("masterPub", ctx_.masterPub);
        signInput.emplace("userPriv", impersonatorKeyIt->second.priv);
        if (!sample.sessionString.empty()) {
            signInput.emplace("sessionString", sample.sessionString);
        }

        try {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::SignRequest>>(*variant);
            sample.signatures.push_back(algo->sign(*req));
            sample.userIds.push_back(victimId);   // claims to be user-(N-1)
            sample.userPubKeys.push_back(victimKeyIt->second.pub);
        } catch (...) {
            continue;
        }

        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 5. Shuffle samples to avoid ordering bias ──
    std::shuffle(samples.begin(), samples.end(), rng_);

    return samples;
}

std::string IdentityVerifyScenario::makeBenchSessionString()
{
    return onlineAlgo_->makeSessionString(
        "bench-" + std::to_string(sessionCounter_++), "IdentityVerify");
}

// ==================================================================
// Private helpers
// ==================================================================

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
