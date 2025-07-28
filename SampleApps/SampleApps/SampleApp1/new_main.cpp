#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For directory validation

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <span>
#include <sddl.h>
#include <limits>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "sample_utils.h"

#include <VbsEnclave\HostApp\Stubs.h>

// Global variables (declared but not initialized, need to be encapsulated)
std::wstring g_helloKeyName;
std::wstring g_pinMessage;
KEY_CREDENTIAL_CACHE_Config g_keyCredentialCacheConfig;
HWND g_hCurWnd;

// Initialize function to set up global variables
void Initialize()
{
    g_helloKeyName = L"MyEncryptionKey-001";
    g_pinMessage = L"Please enter your PIN to access the encryption key.";
    g_keyCredentialCacheConfig = KEY_CREDENTIAL_CACHE_Config(
        KeyCredentialCacheOption_TimeAndUsageBased, 
        300, // timeout in seconds 
        5 // usage count
    );
    g_hCurWnd = GetForegroundWindow();
}

std::vector<uint8_t> OnFirstRun(void* enclave)
{
    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    THROW_IF_FAILED(enclaveInterface.MyEnclaveCreateUserBoundKey(
        g_helloKeyName,
        g_pinMessage,
        g_hCurWnd,
        g_keyCredentialCacheConfig,
        securedEncryptionKeyBytes));

    return securedEncryptionKeyBytes;
    // *** securedEncryptionKeyBytes persisted to disk
}

int EncryptData(
    void* enclave,
    const std::vector<uint8_t>& inputData,
    const std::vector<uint8_t>& securedEncryptionKeyBytes) 
{
    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    HWND hCurWnd = GetForegroundWindow();

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //

    // Call into enclave
    auto encryptedInputBytes = std::vector<uint8_t> {};
    auto tag = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndEncryptData(
        g_helloKeyName,
        g_pinMessage,
        g_hCurWnd,
        g_keyCredentialCacheConfig,
        securedEncryptionKeyBytes,
        inputData,
        encryptedInputBytes,
        tag
    ));

    // TODO: If key not found, then call create followed by a load again

    // ***Save encryptedInputBytes to disk

    return 0;
}
