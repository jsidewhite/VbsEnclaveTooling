#include "pch.h"
#include <VbsEnclave\Enclave\Implementations.h>
#include "crypto.vtl1.h"
#include "utils.vtl1.h"
#include "vengcdll.h" // OS APIs

namespace veil_abi::VTL1_Declarations
{
    std::vector<std::uint8_t> userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
    {
        uint8_t* reportPtr = nullptr;
        size_t reportSize = 0;
        THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(const_cast<uint8_t*>(challenge.data()), challenge.size(), &reportPtr, &reportSize)); // OS CALL
        std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
        CoTaskMemFree(reportPtr);
        return report;
    }
}

namespace veil::vtl1::userboundkey
{
    std::pair<wil::secure_vector<uint8_t>, std::vector<uint8_t>>
    enclave_create_user_bound_key(
        const std::wstring& keyName,
        CACHE_CONFIG cacheConfig,
        HWND windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
    {
        // SESSION
        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(keyName, reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE), (uintptr_t)windowId);

        // EPHEMERAL
        //
        //  Open Question: Have OS API manage ecdh key? i.e. move this into GetUserBoundKeyCreationAuthContext -> echd public key merged into boundKeyBytes
        wil::unique_bcrypt_key ephemeralKeyPair = veil::vtl1::crypto::bcrypt_generate_ecdh_key_pair(BCRYPT_ECDH_P384_ALG_HANDLE);

        // EPHEMERAL PUBLIC
        std::vector<uint8_t> ephemeralPublicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(ephemeralKeyPair.get());

        // AUTH CONTEXT
        USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext;
        THROW_IF_FAILED(GetUserBoundKeyCreationAuthContext(keyName.c_str(), ephemeralKeyPair.get(), authContextBlob.data(), authContextBlob.size(), &authContext)); // OS CALL

        // Validate
        UserBoundKeyAuthContextProperty propCacheConfig;
        propCacheConfig.name = CacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = (uint8_t*)&cacheConfig;
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext, 1, &propCacheConfig)); // OS CALL

        // USERKEY
        auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

        // ENCRYPT USERKEY
        size_t cbBoundKeyBytes;
        std::vector<uint8_t> boundKeyBytes(256);
        THROW_IF_FAILED(ConcealUserBoundKey(authContext, userkeyBytes.data(), userkeyBytes.size(), (void**)boundKeyBytes.data(), &cbBoundKeyBytes)); // OS CALL

        CloseUserBoundKeyAuthContextHandle(authContext); // OS CALL

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
        return { sealedKeyMaterial, ephemeralPublicKeyBytes };
    }

    wil::secure_vector<uint8_t> enclave_load_user_bound_key(
        const std::wstring& keyName,
        CACHE_CONFIG cacheConfig,
        HWND windowId,
        std::vector<uint8_t> sealedBoundKeyBytes,
        std::vector<uint8_t> ephemeralPublicKeyBytes)
    {
        // UNSEAL
        auto boundKeyBytesMaterial = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);
        auto& boundKeyBytes = boundKeyBytesMaterial.first;

        // SESSION
        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(keyName, ephemeralPublicKeyBytes, (uintptr_t)windowId);

        // AUTH CONTEXT
        USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext;
        THROW_IF_FAILED(GetUserBoundKeyLoadingAuthContext(keyName.c_str(), authContextBlob.data(), authContextBlob.size(), &authContext)); // OS CALL

        // Validate
        UserBoundKeyAuthContextProperty propCacheConfig;
        propCacheConfig.name = CacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = (uint8_t*) &cacheConfig;
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext, 1, &propCacheConfig)); // OS CALL

        // DECRYPT USERKEY
        size_t cbUserkeyBytes;
        wil::secure_vector<uint8_t> userkeyBytes(256);
        THROW_IF_FAILED(RevealUserBoundKey(authContext, boundKeyBytes.data(), boundKeyBytes.size(), (void**)userkeyBytes.data(), &cbUserkeyBytes)); // OS CALL

        CloseUserBoundKeyAuthContextHandle(authContext); // OS CALL

        return userkeyBytes;
    }
}
