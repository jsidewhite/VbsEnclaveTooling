#include "pch.h"

#include <string>

#include <VbsEnclave\Enclave\Implementations.h>

#include "vengcdll.h"

#include "crypto.vtl1.h"
#include "utils.vtl1.h"

namespace veil_abi::VTL1_Declarations
{
    std::vector<std::uint8_t> userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
    {
        uint8_t* reportPtr = nullptr;
        size_t reportSize = 0;

        // OS CALL
        THROW_IF_FAILED(GetAttestationReportForUserBoundKey(
            const_cast<uint8_t*>(challenge.data()),
            challenge.size(),
            &reportPtr,
            &reportSize
        ));

        std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
        CoTaskMemFree(reportPtr);
        return report;
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

    wil::secure_vector<uint8_t> enclave_create_user_bound_key(
        const std::wstring& keyName,
        const std::wstring& /* flags */,
        CACHE_CONFIG cacheConfig,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        const std::optional<std::vector<uint8_t>> /*maybeKeyMaterial*/,
        std::vector<uint8_t>& /* resealedMaterial */)
    {
        // Session
        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_establish_session_callback(keyName);

        // EPHEMERAL
        wil::unique_bcrypt_key ephemeralKeyPair = veil::vtl1::crypto::bcrypt_generate_ecdh_key_pair();

        // EPHEMERAL PUBLIC
        std::vector<uint8_t> ephemeralPublicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(ephemeralKeyPair.get());

        // AUTH CONTEXT
        USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext;
        THROW_IF_FAILED(GetAuthContextForUserBoundKeyCreation(keyName.c_str(), ephemeralKeyPair.get(), authContextBlob.data(), authContextBlob.size(), &authContext)); // OS CALL

        // Validate
        std::wstring keyNameFromNgc(keyName.size() + 1, L'\0');
        THROW_IF_FAILED(GetUserBoundKeyAuthContextProperty(authContext, KeyName, (void**)keyNameFromNgc.data(), nullptr)); // OS CALL
        THROW_HR_IF(E_FAIL, keyNameFromNgc != keyName);

        // Validate
        CACHE_CONFIG cacheConfigFromNgc;
        THROW_IF_FAILED(GetUserBoundKeyAuthContextProperty(authContext, CacheConfig, (void**)&cacheConfigFromNgc, nullptr)); // OS CALL
        THROW_HR_IF(E_FAIL, &cacheConfigFromNgc != &cacheConfig);

        // Validate
        bool secureIdIsOwnerId;
        THROW_IF_FAILED(GetUserBoundKeyAuthContextProperty(authContext, SecureIdIsOwnerId, (void**)&secureIdIsOwnerId, nullptr)); // OS CALL
        THROW_HR_IF(E_FAIL, !secureIdIsOwnerId);

        // ECHD + KEK
        std::vector<uint8_t>keyEncryptionKeyBytes(256);
        THROW_IF_FAILED(GetUserBoundKeyAuthContextProperty(authContext, KeyEncryptionKey, (void**)keyEncryptionKeyBytes.data(), nullptr)); // OS CALL
        auto kek = veil::vtl1::crypto::bcrypt_import_key_pair(keyEncryptionKeyBytes);

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
