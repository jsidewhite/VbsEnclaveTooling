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
        void* tempReportPtr = nullptr; // Temporary variable of type void*
        size_t reportSize = 0;

        uint8_t* sessionKeyPtr = nullptr;
        void* tempSessionKeyPtr = nullptr; // Temporary variable of type void*
        size_t sessionKeySize = 0;

        THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(
            const_cast<uint8_t*>(challenge.data()),
            static_cast<UINT32>(challenge.size()),
            &tempReportPtr,
            reinterpret_cast<UINT32*>(&reportSize),
            &tempSessionKeyPtr,
            reinterpret_cast<UINT32*>(&sessionKeySize))); // OS CALL

        reportPtr = static_cast<uint8_t*>(tempReportPtr); // Cast back to uint8_t*
        std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
        CoTaskMemFree(reportPtr);

        sessionKeyPtr = static_cast<uint8_t*>(tempSessionKeyPtr); // Cast back to uint8_t*
        std::vector<uint8_t> sessionKey(sessionKeyPtr, sessionKeyPtr + sessionKeySize);
        CoTaskMemFree(sessionKeyPtr);

        return report;
    }
}

namespace veil::vtl1::userboundkey
{

    std::vector<uint8_t> GetEphemeralPublicKeyBytesFromBoundKeyBytes(wil::secure_vector<uint8_t> /*boundKeyBytes*/)
    {
        // TODO: implemententation
        return {};
    }


    wil::secure_vector<uint8_t> enclave_create_user_bound_key(
        const std::wstring& keyName,
        CACHE_CONFIG cacheConfig,
        const std::wstring& message,
        HWND windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
    {
        // SESSION
        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(keyName, reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE), message, (uintptr_t)windowId);

        // AUTH CONTEXT
        USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext;
        THROW_IF_FAILED(GetUserBoundKeyCreationAuthContext(
            keyName.c_str(), // Pass the keyName as a wide string
            authContextBlob.data(), // Pass the pointer to the authContextBlob
            static_cast<UINT32>(authContextBlob.size()), // Pass the size of the authContextBlob
            &authContext // Pass the output handle
        )); // OS CALL

        // Validate
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig; // Correct enum value
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = reinterpret_cast<void*>(&cacheConfig);

        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext, 1, &propCacheConfig)); // OS CALL

        // USERKEY
        auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

        // ENCRYPT USERKEY
        std::vector<uint8_t> boundKeyBytes(256);
        UINT32 cbBoundKeyBytes = static_cast<UINT32>(boundKeyBytes.size()); // Ensure the type matches
        THROW_IF_FAILED(ProtectUserBoundKey(authContext, userkeyBytes.data(), static_cast<UINT32>(userkeyBytes.size()), (void**)boundKeyBytes.data(), &cbBoundKeyBytes)); // OS CALL
        CloseUserBoundKeyAuthContextHandle(authContext); // OS CALL

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
        return sealedKeyMaterial;
    }

    std::vector<uint8_t> enclave_load_user_bound_key(
        const std::wstring& keyName,
        CACHE_CONFIG cacheConfig,
        const std::wstring& message,
        HWND windowId,
        std::vector<uint8_t> sealedBoundKeyBytes)
    {
        // UNSEAL
        auto boundKeyBytesMaterial = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);
        auto& boundKeyBytes = boundKeyBytesMaterial.first;
        std::vector<uint8_t> ephemeralPublicKeyBytes = GetEphemeralPublicKeyBytesFromBoundKeyBytes(boundKeyBytes);

        // SESSION
        auto secretAndAuthContextBlob = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(keyName, ephemeralPublicKeyBytes, message, (uintptr_t)windowId);

        auto& secret = secretAndAuthContextBlob.secret;
        auto& authContextBlob = secretAndAuthContextBlob.authorizationContext;

        // AUTH CONTEXT
        USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext;
        THROW_IF_FAILED(GetUserBoundKeyLoadingAuthContext(
            keyName.c_str(),
            authContextBlob.data(),
            static_cast<UINT32>(authContextBlob.size()), // Explicit cast to UINT32 to resolve C4267
            &authContext)); // OS CALL

        // Validate
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = (uint8_t*) &cacheConfig;
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext, 1, &propCacheConfig)); // OS CALL

        // DECRYPT USERKEY
        UINT32 cbUserkeyBytes = 0; // Declare cbUserkeyBytes as UINT32
        std::vector<uint8_t> userkeyBytes(256);
        THROW_IF_FAILED(UnprotectUserBoundKey(
            authContext,
            secret.data(),
            static_cast<UINT32>(secret.size()), // Explicit cast to UINT32
            boundKeyBytes.data(),
            static_cast<UINT32>(boundKeyBytes.size()), // Explicit cast to UINT32
            (void**)userkeyBytes.data(),
            &cbUserkeyBytes)); // OS CALL

        CloseUserBoundKeyAuthContextHandle(authContext); // OS CALL

        return userkeyBytes;
    }
}
