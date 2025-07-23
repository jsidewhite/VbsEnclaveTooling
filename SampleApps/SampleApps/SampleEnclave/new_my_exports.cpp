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

//
// Secured encryption key
//
HRESULT VbsEnclave::VTL1_Declarations::EnclaveCreateUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _In_ KEY_CREDENTIAL_CACHE_CONFIG keyCredentialCacheConfiguration,
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // TODO: if the key already exists, we should skip creating a new key?

    securedEncryptionKeyBytes = veil::vtl1::userboundkey::enclave_create_user_bound_key(
        helloKeyName,
        keyCredentialCacheConfiguration, // TODO: is this needed?
        pinMessage,
        windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE);

    return S_OK;
}

HRESULT VbsEnclave::VTL1_Declarations::EnclaveLoadUserBoundKeyAndEncryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _In_ KEY_CREDENTIAL_CACHE_CONFIG keyCredentialCacheConfiguration,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& inputData,
    _Out_  std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_  std::vector<std::uint8_t>& tag)
{
    using namespace veil::vtl1::vtl0_functions;

    // if (!IsUserBoundKeyLoaded()) TODO?
    auto encryptionKey = veil::vtl1::userboundkey::enclave_load_user_bound_key(
        helloKeyName,
        keyCredentialCacheConfiguration, // TODO: is this needed?
        pinMessage,
        windowId,
        securedEncryptionKeyBytes);

    //
    // Now let's encrypt the input data with our encryption key
    //

    // Encrypting the user input data
    auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(inputData.c_str()), veil::vtl1::crypto::zero_nonce);

    // Return the encrypted input to vtl0 host caller...
    encryptedInputBytes.assign(encryptedText.begin(), encryptedText.end());
    tag.assign(encryptionTag.begin(), encryptionTag.end());

    return true;
}
