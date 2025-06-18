#pragma once

#ifndef VENGCDLL_H
#define VENGCDLL_H

//
// Exports for vengcdll.dll (new OS DLL in VTL1)
//

// Attestation report generation API for user bound keys.
// Generates a session key, passes session key and provided challenge to EnclaveGetAttestationReport,
// encrypts the attestation report with EnclaveEncryptDataForTrustlet, returns the encrypted report. 
HRESULT InitializeUserBoundKeySessionInfo(
    _In_ uint8_t* challenge,
    _In_ size_t challengeSize,
    _Out_ uint8_t** report,
    _Out_ size_t* reportSize
);

// Auth Context APIs
typedef void* USER_BOUND_KEY_AUTH_CONTEXT_HANDLE;

BOOL CloseUserBoundKeyAuthContextHandle(
    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle);

struct CACHE_CONFIG {
    uint32_t cacheType;
    uint32_t cacheTimeout;
    uint32_t cacheCallCount;
};

enum UserBoundKeyAuthContextProperties {
    CacheConfig = 0, // The cache configuration for the user bound key, encoded as a CACHE_CONFIG structure
};

// Called as part of the flow when creating a new user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob,
// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the NGC side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
HRESULT GetUserBoundKeyCreationAuthContext(
    _In_ PCWSTR keyName,
    _In_ BCRYPT_KEY_HANDLE enclaveKey, // The enclave key handle used to to perform key establishment.
    _In_ uint8_t* authContextBlob, // auth context generated as part of RequestCreateAsync
    _In_ size_t authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

// Called as part of the flow when loading an existing user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob.
HRESULT GetUserBoundKeyLoadingAuthContext(
    _In_ PCWSTR keyName,
    _In_ uint8_t* authContextBlob, // auth context generated as part of RequestCreateAsync 
    _In_ size_t authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

struct UserBoundKeyAuthContextProperty
{
    UserBoundKeyAuthContextProperties name;
    size_t size;
    uint8_t* value;
};

HRESULT ValidateUserBoundKeyAuthContext(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ size_t count,
    _In_ UserBoundKeyAuthContextProperty* values
);

// Encrypt the user key and produce material to save to disk
HRESULT ConcealUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_ uint8_t* userKey,
    _In_ size_t cbUserKey,
    _Out_ void** boundKey,
    _Inout_ size_t* cbBoundKey
);

// Decrypt the user key from material from disk
HRESULT RevealUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_ uint8_t* boundKey,
    _In_ size_t cbBoundKey,
    _Out_ void** userKey,
    _Inout_ size_t* cbUserKey
);

#endif // VENGCDLL_H
