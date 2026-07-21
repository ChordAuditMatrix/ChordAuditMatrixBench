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
 *          verification accuracy across iterations.
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-05
 */

#include <ChordAuditMatrixBench/identity_verify_scenario.h>

// ── Framework ──
#include <ChordAuditMatrixBench/benchmark_types.h>

// ── Identity manager ──
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_manager.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_request.h"

// ── AuditDataMap for algorithm input ──
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <random>
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
    config_ = config;

    // Seed the RNG if pseudo-random mode is requested
    if (config.usePseudoRandom) {
        rng_.seed(config.seed);
    }

    // ── Step 1: Use injected manager ──
    ctx_.manager = manager_;

    // ── Step 2: Generate master key pair ──
    auto initMs = measureMs([&] {
        auto [pub, priv] = ctx_.manager->getIdentityAlgorithm(algorithmType_)->generateMasterKey();
        ctx_.masterPub = pub;
        ctx_.masterPriv = priv;
    });
    ctx_.setupTimings.initAlgoMs = initMs;

    // ── Step 3: Derive per-user key pairs ──
    auto genKeysMs = measureMs([&] {
        for (std::size_t i = 0; i < config.numUsers; ++i) {
            auto userId = "user-" + std::to_string(i);
            auto [uPub, uPriv] = ctx_.manager->getIdentityAlgorithm(algorithmType_)->deriveUserKey(
                *ctx_.masterPub, *ctx_.masterPriv, userId);
            ctx_.userKeys[userId] = {uPub, uPriv};
        }
    });
    ctx_.setupTimings.genKeysMs = genKeysMs;

    // ── Step 4: Generate labeled test samples (measure signing time) ──
    auto signMs = measureMs([&] {
        ctx_.testSamples = generateTestSamples(config);
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

    // ── Compute accuracy rate ──
    std::size_t total = lastTA_ + lastFA_ + lastTR_ + lastFR_;
    lastAccuracyRate_ = (total > 0)
        ? static_cast<double>(lastTA_ + lastTR_) / static_cast<double>(total)
        : 0.0;

    // ── Record average timings per sample ──
    std::size_t sampleCount = ctx_.testSamples.size();
    lastTimings_ = StageTimings{};
    lastTimings_.signMs = (sampleCount > 0) ? ctx_.setupTimings.signMs / sampleCount : 0;
    lastTimings_.verifyMs = (sampleCount > 0) ? totalVerifyMs / sampleCount : 0;
    lastTimings_.aggregateVerifyMs = totalVerifyMs;

    // ── Record message sizes (average per sample) ──
    lastMessageSizes_ = MessageSizes{};
    lastMessageSizes_.signatureBytes =
        (sampleCount > 0) ? totalSignatureBytes / sampleCount : 0;
    lastMessageSizes_.verifyRequestBytes =
        (sampleCount > 0) ? totalVerifyRequestBytes / sampleCount : 0;

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
// generateTestSamples()
// ==================================================================

std::vector<IdentitySampleLabel>
IdentityVerifyScenario::generateTestSamples(const BenchmarkConfig& config)
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
