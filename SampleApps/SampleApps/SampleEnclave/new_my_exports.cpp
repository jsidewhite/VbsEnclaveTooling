// Copyright (c) Microsoft Corporation.
//

#include "pch.h"

#include <array>
#include <stdexcept>

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\logger.vtl1.h>
#include <veil\enclave\taskpool.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>

#include <VbsEnclave\Enclave\Implementations.h>
#include <vector>

BCRYPT_KEY_HANDLE g_encryptionKeyHandle;

bool IsUBKLoaded()
{
    // Check if the key handle is valid
    if (g_encryptionKeyHandle == nullptr)
    {
        return false;
    }

    return true;
}

//
// Secured encryption key
//
HRESULT VbsEnclave::VTL1_Declarations::MyEnclaveCreateUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _In_ KEY_CREDENTIAL_CACHE_CONFIG keyCredentialCacheConfiguration,
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    try
    {
        securedEncryptionKeyBytes = veil::vtl1::userboundkey::enclave_create_user_bound_key(
            helloKeyName,
            keyCredentialCacheConfiguration,
            pinMessage,
            windowId,
            ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE);
    }
    catch (const std::exception& e)
    {
        return E_FAIL;
    }

    g_encryptionKeyHandle = veil::vtl1::crypto::create_symmetric_key(securedEncryptionKeyBytes);

    return S_OK;
}

HRESULT VbsEnclave::VTL1_Declarations::MyEnclaveLoadUserBoundKeyAndEncryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _In_ KEY_CREDENTIAL_CACHE_CONFIG keyCredentialCacheConfiguration,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ std::vector<uint8_t>& inputData,
    _Out_  std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_  std::vector<std::uint8_t>& tag)
{
    using namespace veil::vtl1::vtl0_functions;

    BCRYPT_KEY_HANDLE encryptionKey = nullptr;
    if (!IsUBKLoaded())
    {
        encryptionKey = veil::vtl1::userboundkey::enclave_load_user_bound_key(
            helloKeyName,
            keyCredentialCacheConfiguration,
            pinMessage,
            windowId,
            securedEncryptionKeyBytes);
    }
    else
    {
        encryptionKey = g_encryptionKeyHandle;
    }

    //
    // Now let's encrypt the input data with our encryption key
    //

    // Encrypting the user input data
    auto [encryptedBlob, encryptionTag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(inputData), veil::vtl1::crypto::zero_nonce);

    // Return the encrypted input to vtl0 host caller...
    encryptedInputBytes.assign(encryptedBlob.begin(), encryptedBlob.end());
    tag.assign(encryptionTag.begin(), encryptionTag.end());

    return true;
}


