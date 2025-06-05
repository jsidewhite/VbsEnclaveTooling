// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <string>

#include <VbsEnclave\Enclave\Implementations.h>

#include "crypto.vtl1.h"
#include "utils.vtl1.h"

// Gudge's notes kept here
/*
std::vector<uint8_t> GetAttestationReportForUserBoundKey(std::vector<uint8_t> challenge, std::array<uint8_t, 32> sessionKey); // Returns attestation report encrypted for NGC containing session key and challenge

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> GetAttestationReportForUserBoundKey(std::vector<uint8_t> challenge, std::array<uint8_t, 32> sessionKey); // Returns attestation report encrypted for NGC containing session key and challenge, also returns the session key



// Open question – is BCryptGenRandom of 32 bytes always OK?

API(s) to verify ExportPublicKey, SecureIdOwnerIdMatch, CacheConfiguration, ExportKEK

std::vector<uint8_t> GetKEKFromCreateAuthContext (BCRYPT_KEY_HANDLE enclavePrivateKey, std::string keyName, CACHE_CONFIG expectedCacheConfig, OTHER_CONFIG expectedConfig, std::vector<uint8_t> authContextBlob); // returns KEK

std::vector<uint8_t> GetKEKFromLoadAuthContext (std::string keyName, CACHE_CONFIG expectedCacheConfig, OTHER_CONFIG expectedConfig, std::vector<uint8_t> authContextBlob); // returns KEK

// Open question – Separate Apis for each message?

// Open question – NGC fails if ownerid != secureid?

API to derive KEK (Create flow only)

BCRYPT_KEY_HANDLE DeriveKEKForUserBoundKey(BCRYPT_KEY_HANDLE sharedSecret);
*/


// NewOsDll.dll exports
#define CACHE_CONFIG int
#define OTHER_CONFIG int
std::vector<uint8_t> GetAttestationReportForUserBoundKey(std::vector<uint8_t> challenge, std::array<uint8_t, 32> sessionKey); // Returns attestation report encrypted for NGC containing session key and challenge
std::vector<uint8_t> GetKEKFromCreateAuthContext(BCRYPT_KEY_HANDLE enclavePrivateKey, std::wstring keyName, CACHE_CONFIG expectedCacheConfig, OTHER_CONFIG expectedConfig, std::vector<uint8_t> authContextBlob); // returns KEK


namespace veil_abi::VTL1_Declarations
{
    std::vector<std::uint8_t> userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
    {
        auto sessionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
        return GetAttestationReportForUserBoundKey(challenge, sessionKeyBytes); // !!!!!!!! OS CALL !!!!!!!!
    }
}

namespace veil::vtl1::userboundkey
{
    struct encrypted_symmetric_key_information
    {
        uint8_t nonce[veil::vtl1::crypto::NONCE_SIZE];
        uint8_t tag[veil::vtl1::crypto::TAG_SIZE];
        uint8_t key[veil::vtl1::crypto::SYMMETRIC_KEY_SIZE_BYTES];
        uint8_t ephemeralKey[veil::vtl1::crypto::SYMMETRIC_KEY_SIZE_BYTES];
        //uint8_t keyName[sizeof(uint64_t)]; // todo?
        //uint8_t keyUsage[sizeof(uint64_t)]; // todo?

        // Implicit conversion operator to std::span
        operator std::span<uint8_t const>() const
        {
            return {reinterpret_cast<uint8_t const*>(this), sizeof(encrypted_symmetric_key_information)};
        }
    };

    wil::secure_vector<uint8_t> enclave_load_user_bound_key(
        const std::wstring& keyName,
        const std::wstring& /* flags */,
        CACHE_CONFIG expectedCacheConfig,
        OTHER_CONFIG expectedConfig,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        const std::optional<std::vector<uint8_t>> maybeKeyMaterial,
        std::vector<uint8_t>& /* resealedMaterial */)
    {
        // Session
        auto authContext = veil_abi::VTL0_Callbacks::userboundkey_establish_session_callback(keyName); // "Callback 1"

        // EPHEMERAL
        wil::unique_bcrypt_key ephemeralKeyPair = veil::vtl1::crypto::bcrypt_generate_ecdh_key_pair();

        // EPHEMERAL PUBLIC
        std::vector<uint8_t> ephemeralPublicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(ephemeralKeyPair.get());

        // ECHD + KEK
        auto kekBytes = GetKEKFromCreateAuthContext(ephemeralKeyPair.get(), keyName, expectedCacheConfig, expectedConfig, authContext); // !!!!!!!! OS CALL !!!!!!!!
        auto kek = veil::vtl1::crypto::bcrypt_import_key_pair(kekBytes);

        // USERKEY
        auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

        // EncryptWithKEK
        auto nonce = veil::vtl1::crypto::generate_random<sizeof(encrypted_symmetric_key_information::nonce)>();
        auto [userkeyEncrypted, tag] = veil::vtl1::crypto::encrypt(kek.get(), userkeyBytes, nonce);

        // KEY_MATERIAL
        encrypted_symmetric_key_information keyMaterial;
        veil::vtl1::copy_span(nonce, keyMaterial.nonce);
        veil::vtl1::copy_span(tag, keyMaterial.tag);
        veil::vtl1::copy_span(userkeyEncrypted, keyMaterial.key);
        veil::vtl1::copy_span(ephemeralPublicKeyBytes, keyMaterial.ephemeralKey);

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(keyMaterial, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);

        return sealedKeyMaterial;
    }
}
