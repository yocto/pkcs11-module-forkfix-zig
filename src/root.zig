const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("dlfcn.h");
    @cInclude("czig.h");
});
const std = @import("std");

const cryptokiVersion: c.CK_VERSION = c.CK_VERSION{
    .major = 3,
    .minor = 1,
};

const interfaces: []const c.CK_INTERFACE = &.{.{
    .pInterfaceName = @constCast(@as([*c]const u8, @ptrCast("PKCS 11".ptr))),
    .pFunctionList = &functionList30,
    .flags = 0x0,
}};

var functionList = c.CK_FUNCTION_LIST{
    .version = cryptokiVersion,
    // Version 2.0 and later
    .C_Initialize = &C_Initialize,
    .C_Finalize = &C_Finalize,
    .C_GetInfo = &C_GetInfo,
    .C_GetFunctionList = &C_GetFunctionList,
    .C_GetSlotList = &C_GetSlotList,
    .C_GetSlotInfo = &C_GetSlotInfo,
    .C_GetTokenInfo = &C_GetTokenInfo,
    .C_GetMechanismList = &C_GetMechanismList,
    .C_GetMechanismInfo = &C_GetMechanismInfo,
    .C_InitToken = &C_InitToken,
    .C_InitPIN = &C_InitPIN,
    .C_SetPIN = &C_SetPIN,
    .C_OpenSession = &C_OpenSession,
    .C_CloseSession = &C_CloseSession,
    .C_CloseAllSessions = &C_CloseAllSessions,
    .C_GetSessionInfo = &C_GetSessionInfo,
    .C_GetOperationState = &C_GetOperationState,
    .C_SetOperationState = &C_SetOperationState,
    .C_Login = &C_Login,
    .C_Logout = &C_Logout,
    .C_CreateObject = &C_CreateObject,
    .C_CopyObject = &C_CopyObject,
    .C_DestroyObject = &C_DestroyObject,
    .C_GetObjectSize = &C_GetObjectSize,
    .C_GetAttributeValue = &C_GetAttributeValue,
    .C_SetAttributeValue = &C_SetAttributeValue,
    .C_FindObjectsInit = &C_FindObjectsInit,
    .C_FindObjects = &C_FindObjects,
    .C_FindObjectsFinal = &C_FindObjectsFinal,
    .C_EncryptInit = &C_EncryptInit,
    .C_Encrypt = &C_Encrypt,
    .C_EncryptUpdate = &C_EncryptUpdate,
    .C_EncryptFinal = &C_EncryptFinal,
    .C_DecryptInit = &C_DecryptInit,
    .C_Decrypt = &C_Decrypt,
    .C_DecryptUpdate = &C_DecryptUpdate,
    .C_DecryptFinal = &C_DecryptFinal,
    .C_DigestInit = &C_DigestInit,
    .C_Digest = &C_Digest,
    .C_DigestUpdate = &C_DigestUpdate,
    .C_DigestKey = &C_DigestKey,
    .C_DigestFinal = &C_DigestFinal,
    .C_SignInit = &C_SignInit,
    .C_Sign = &C_Sign,
    .C_SignUpdate = &C_SignUpdate,
    .C_SignFinal = &C_SignFinal,
    .C_SignRecoverInit = &C_SignRecoverInit,
    .C_SignRecover = &C_SignRecover,
    .C_VerifyInit = &C_VerifyInit,
    .C_Verify = &C_Verify,
    .C_VerifyUpdate = &C_VerifyUpdate,
    .C_VerifyFinal = &C_VerifyFinal,
    .C_VerifyRecoverInit = &C_VerifyRecoverInit,
    .C_VerifyRecover = &C_VerifyRecover,
    .C_DigestEncryptUpdate = &C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = &C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = &C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = &C_DecryptVerifyUpdate,
    .C_GenerateKey = &C_GenerateKey,
    .C_GenerateKeyPair = &C_GenerateKeyPair,
    .C_WrapKey = &C_WrapKey,
    .C_UnwrapKey = &C_UnwrapKey,
    .C_DeriveKey = &C_DeriveKey,
    .C_SeedRandom = &C_SeedRandom,
    .C_GenerateRandom = &C_GenerateRandom,
    .C_GetFunctionStatus = &C_GetFunctionStatus,
    .C_CancelFunction = &C_CancelFunction,
    // Version 2.1 and later
    .C_WaitForSlotEvent = &C_WaitForSlotEvent,
};

var functionList30 = c.CK_FUNCTION_LIST_3_0{
    .version = cryptokiVersion,
    // Version 2.0 and later
    .C_Initialize = &C_Initialize,
    .C_Finalize = &C_Finalize,
    .C_GetInfo = &C_GetInfo,
    .C_GetFunctionList = &C_GetFunctionList,
    .C_GetSlotList = &C_GetSlotList,
    .C_GetSlotInfo = &C_GetSlotInfo,
    .C_GetTokenInfo = &C_GetTokenInfo,
    .C_GetMechanismList = &C_GetMechanismList,
    .C_GetMechanismInfo = &C_GetMechanismInfo,
    .C_InitToken = &C_InitToken,
    .C_InitPIN = &C_InitPIN,
    .C_SetPIN = &C_SetPIN,
    .C_OpenSession = &C_OpenSession,
    .C_CloseSession = &C_CloseSession,
    .C_CloseAllSessions = &C_CloseAllSessions,
    .C_GetSessionInfo = &C_GetSessionInfo,
    .C_GetOperationState = &C_GetOperationState,
    .C_SetOperationState = &C_SetOperationState,
    .C_Login = &C_Login,
    .C_Logout = &C_Logout,
    .C_CreateObject = &C_CreateObject,
    .C_CopyObject = &C_CopyObject,
    .C_DestroyObject = &C_DestroyObject,
    .C_GetObjectSize = &C_GetObjectSize,
    .C_GetAttributeValue = &C_GetAttributeValue,
    .C_SetAttributeValue = &C_SetAttributeValue,
    .C_FindObjectsInit = &C_FindObjectsInit,
    .C_FindObjects = &C_FindObjects,
    .C_FindObjectsFinal = &C_FindObjectsFinal,
    .C_EncryptInit = &C_EncryptInit,
    .C_Encrypt = &C_Encrypt,
    .C_EncryptUpdate = &C_EncryptUpdate,
    .C_EncryptFinal = &C_EncryptFinal,
    .C_DecryptInit = &C_DecryptInit,
    .C_Decrypt = &C_Decrypt,
    .C_DecryptUpdate = &C_DecryptUpdate,
    .C_DecryptFinal = &C_DecryptFinal,
    .C_DigestInit = &C_DigestInit,
    .C_Digest = &C_Digest,
    .C_DigestUpdate = &C_DigestUpdate,
    .C_DigestKey = &C_DigestKey,
    .C_DigestFinal = &C_DigestFinal,
    .C_SignInit = &C_SignInit,
    .C_Sign = &C_Sign,
    .C_SignUpdate = &C_SignUpdate,
    .C_SignFinal = &C_SignFinal,
    .C_SignRecoverInit = &C_SignRecoverInit,
    .C_SignRecover = &C_SignRecover,
    .C_VerifyInit = &C_VerifyInit,
    .C_Verify = &C_Verify,
    .C_VerifyUpdate = &C_VerifyUpdate,
    .C_VerifyFinal = &C_VerifyFinal,
    .C_VerifyRecoverInit = &C_VerifyRecoverInit,
    .C_VerifyRecover = &C_VerifyRecover,
    .C_DigestEncryptUpdate = &C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = &C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = &C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = &C_DecryptVerifyUpdate,
    .C_GenerateKey = &C_GenerateKey,
    .C_GenerateKeyPair = &C_GenerateKeyPair,
    .C_WrapKey = &C_WrapKey,
    .C_UnwrapKey = &C_UnwrapKey,
    .C_DeriveKey = &C_DeriveKey,
    .C_SeedRandom = &C_SeedRandom,
    .C_GenerateRandom = &C_GenerateRandom,
    .C_GetFunctionStatus = &C_GetFunctionStatus,
    .C_CancelFunction = &C_CancelFunction,
    // Version 2.1 and later
    .C_WaitForSlotEvent = &C_WaitForSlotEvent,
    // Version 3.0 and later
    .C_GetInterfaceList = &C_GetInterfaceList,
    .C_GetInterface = &C_GetInterface,
    .C_LoginUser = &C_LoginUser,
    .C_SessionCancel = &C_SessionCancel,
    .C_MessageEncryptInit = &C_MessageEncryptInit,
    .C_EncryptMessage = &C_EncryptMessage,
    .C_EncryptMessageBegin = &C_EncryptMessageBegin,
    .C_EncryptMessageNext = &C_EncryptMessageNext,
    .C_MessageEncryptFinal = &C_MessageEncryptFinal,
    .C_MessageDecryptInit = &C_MessageDecryptInit,
    .C_DecryptMessage = &C_DecryptMessage,
    .C_DecryptMessageBegin = &C_DecryptMessageBegin,
    .C_DecryptMessageNext = &C_DecryptMessageNext,
    .C_MessageDecryptFinal = &C_MessageDecryptFinal,
    .C_MessageSignInit = &C_MessageSignInit,
    .C_SignMessage = &C_SignMessage,
    .C_SignMessageBegin = &C_SignMessageBegin,
    .C_SignMessageNext = &C_SignMessageNext,
    .C_MessageSignFinal = &C_MessageSignFinal,
    .C_MessageVerifyInit = &C_MessageVerifyInit,
    .C_VerifyMessage = &C_VerifyMessage,
    .C_VerifyMessageBegin = &C_VerifyMessageBegin,
    .C_VerifyMessageNext = &C_VerifyMessageNext,
    .C_MessageVerifyFinal = &C_MessageVerifyFinal,
};

// var library: std.DynLib = undefined;
var libraryHandle: ?*anyopaque = null;
var libraryPID: i32 = 0;

fn getPID() i32 {
    return std.os.linux.getpid();
}

fn getDynamicLibrary() ?*anyopaque {
    const pid: i32 = getPID();
    if (libraryHandle == null or libraryPID == -1 or libraryPID != pid) {
        log("Fork detected. Having process id {} now. Reloading submodule.\n", .{pid});
        if (libraryHandle != null) {
            _ = c.dlerror();
            _ = c.dlclose(libraryHandle);
            const err = c.dlerror();
            if (err != null) {
                log("Error when closing dynamic library: {s}\n", .{err});
            }
        }

        _ = c.dlerror();
        libraryHandle = c.dlmopen(c.LM_ID_NEWLM, "/usr/lib/pkcs11/pkcs11-kmip.so", c.RTLD_NOW | c.RTLD_LOCAL | c.RTLD_DEEPBIND);
        const err: [*c]u8 = c.dlerror();
        if (err != null) {
            log("Error when opening dynamic library: {s}\n", .{err});
        }
        if (libraryHandle == null) {
            return null;
        }
        libraryPID = pid;
    }
    return libraryHandle;
}

fn getDynamicLibraryFunction(comptime T: type, functionName: [:0]const u8) T {
    const lh = getDynamicLibrary();
    if (lh == null) {
        return null;
    }
    _ = c.dlerror();
    const symbol = c.dlsym(lh, functionName);
    const err = c.dlerror();
    if (err != null) {
        log("Error when getting symbol from dynamic library: {s}\n", .{err});
    }

    return @as(T, @ptrCast(symbol));
}

fn log(comptime fmt: []const u8, args: anytype) void {
    const text = std.fmt.allocPrint(std.heap.page_allocator, fmt, args) catch return;
    defer std.heap.page_allocator.free(text);
    _ = std.posix.write(2, text) catch {};
}

export fn C_CancelFunction(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_CancelFunction, "C_CancelFunction");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_CloseAllSessions(slotID: c.CK_SLOT_ID) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_CloseAllSessions, "C_CloseAllSessions");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID);
}

export fn C_CloseSession(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_CloseSession, "C_CloseSession");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

//usCount c.CK_USHORT (v1.0)
export fn C_CopyObject(hSession: c.CK_SESSION_HANDLE, hObject: c.CK_OBJECT_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG, phNewObject: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_CopyObject, "C_CopyObject");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hObject, pTemplate, ulCount, phNewObject);
}

//usCount c.CK_USHORT (v1.0)
export fn C_CreateObject(hSession: c.CK_SESSION_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG, phObject: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_CreateObject, "C_CreateObject");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pTemplate, ulCount, phObject);
}

//usEncryptedDataLen c.CK_USHORT (v1.0)
//pusDataLen c.CK_USHORT_PTR (v1.0)
export fn C_Decrypt(hSession: c.CK_SESSION_HANDLE, pEncryptedData: c.CK_BYTE_PTR, ulEncryptedDataLen: c.CK_ULONG, pData: c.CK_BYTE_PTR, pulDataLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Decrypt, "C_Decrypt");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}

export fn C_DecryptDigestUpdate(hSession: c.CK_SESSION_HANDLE, pEncryptedPart: c.CK_BYTE_PTR, ulEncryptedPartLen: c.CK_ULONG, pPart: c.CK_BYTE_PTR, pulPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptDigestUpdate, "C_DecryptDigestUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//usLastPartLen c.CK_USHORT_PTR (v1.0)
export fn C_DecryptFinal(hSession: c.CK_SESSION_HANDLE, pLastPart: c.CK_BYTE_PTR, pulLastPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptFinal, "C_DecryptFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pLastPart, pulLastPartLen);
}

export fn C_DecryptInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptInit, "C_DecryptInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_DecryptMessage(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pAssociatedData: c.CK_BYTE_PTR, ulAssociatedDataLen: c.CK_ULONG, pCiphertext: c.CK_BYTE_PTR, ulCiphertextLen: c.CK_ULONG, pPlaintext: c.CK_BYTE_PTR, pulPlaintextLen: c.CK_ULONG_PTR) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptMessage, "C_DecryptMessage");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen, pPlaintext, pulPlaintextLen);
}

export fn C_DecryptMessageBegin(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pAssociatedData: c.CK_BYTE_PTR, ulAssociatedDataLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptMessageBegin, "C_DecryptMessageBegin");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
}

export fn C_DecryptMessageNext(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pCiphertextPart: c.CK_BYTE_PTR, ulCiphertextPartLen: c.CK_ULONG, pPlaintextPart: c.CK_BYTE_PTR, pulPlaintextPartLen: c.CK_ULONG_PTR, flags: c.CK_FLAGS) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptMessageNext, "C_DecryptMessageNext");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, flags);
}

//usEncryptedPartLen c.CK_USHORT (v1.0)
//pusPartLen c.CK_USHORT_PTR (v1.0)
export fn C_DecryptUpdate(hSession: c.CK_SESSION_HANDLE, pEncryptedPart: c.CK_BYTE_PTR, ulEncryptedPartLen: c.CK_ULONG, pPart: c.CK_BYTE_PTR, pulPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptUpdate, "C_DecryptUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

export fn C_DecryptVerifyUpdate(hSession: c.CK_SESSION_HANDLE, pEncryptedPart: c.CK_BYTE_PTR, ulEncryptedPartLen: c.CK_ULONG, pPart: c.CK_BYTE_PTR, pulPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_DecryptVerifyUpdate, "C_DecryptVerifyUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

//usAttributeCount c.CK_USHORT (v1.0)
export fn C_DeriveKey(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hBaseKey: c.CK_OBJECT_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulAttributeCount: c.CK_ULONG, phKey: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DeriveKey, "C_DeriveKey");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}

export fn C_DestroyObject(hSession: c.CK_SESSION_HANDLE, hObject: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DestroyObject, "C_DestroyObject");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hObject);
}

//usDataLen c.CK_USHORT (v1.0)
//pusDigestLen c.CK_USHORT_PTR (v1.0)
export fn C_Digest(hSession: c.CK_SESSION_HANDLE, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pDigest: c.CK_BYTE_PTR, pulDigestLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Digest, "C_Digest");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

export fn C_DigestEncryptUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG, pEncryptedPart: c.CK_BYTE_PTR, pulEncryptedPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_DigestEncryptUpdate, "C_DigestEncryptUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//pusDigestLen c.CK_USHORT_PTR (v1.0)
export fn C_DigestFinal(hSession: c.CK_SESSION_HANDLE, pDigest: c.CK_BYTE_PTR, pulDigestLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DigestFinal, "C_DigestFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pDigest, pulDigestLen);
}

export fn C_DigestInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DigestInit, "C_DigestInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism);
}

export fn C_DigestKey(hSession: c.CK_SESSION_HANDLE, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_DigestKey, "C_DigestKey");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hKey);
}

//usPartLen c.CK_USHORT (v1.0)
export fn C_DigestUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_DigestUpdate, "C_DigestUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen);
}

//usDataLen c.CK_USHORT (v1.0)
//pusEncryptedDataLen c.CK_USHORT_PTR (v1.0)
export fn C_Encrypt(hSession: c.CK_SESSION_HANDLE, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pEncryptedData: c.CK_BYTE_PTR, pulEncryptedDataLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Encrypt, "C_Encrypt");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

//pusEncryptedPartLen c.CK_USHORT_PTR (v1.0)
export fn C_EncryptFinal(hSession: c.CK_SESSION_HANDLE, pLastEncryptedPart: c.CK_BYTE_PTR, pulLastEncryptedPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptFinal, "C_EncryptFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
}

export fn C_EncryptInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptInit, "C_EncryptInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_EncryptMessage(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pAssociatedData: c.CK_BYTE_PTR, ulAssociatedDataLen: c.CK_ULONG, pPlaintext: c.CK_BYTE_PTR, ulPlaintextLen: c.CK_ULONG, pCiphertext: c.CK_BYTE_PTR, pulCiphertextLen: c.CK_ULONG_PTR) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptMessage, "C_EncryptMessage");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen, pCiphertext, pulCiphertextLen);
}

export fn C_EncryptMessageBegin(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pAssociatedData: c.CK_BYTE_PTR, ulAssociatedDataLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptMessageBegin, "C_EncryptMessageBegin");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
}

export fn C_EncryptMessageNext(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pPlaintextPart: c.CK_BYTE_PTR, ulPlaintextPartLen: c.CK_ULONG, pCiphertextPart: c.CK_BYTE_PTR, pulCiphertextPartLen: c.CK_ULONG_PTR, flags: c.CK_FLAGS) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptMessageNext, "C_EncryptMessageNext");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, flags);
}

//usPartLen c.CK_USHORT (v1.0)
////pusEncryptedPartLen c.CK_USHORT_PTR (v1.0)
export fn C_EncryptUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG, pEncryptedPart: c.CK_BYTE_PTR, pulEncryptedPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_EncryptUpdate, "C_EncryptUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

export fn C_Finalize(pReserved: c.CK_VOID_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_Finalize, "C_Finalize");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(pReserved);
}

//usMaxObjectCount c.CK_USHORT (v1.0)
//pusObjectCount c.CK_USHORT_PTR (v1.0)
export fn C_FindObjects(hSession: c.CK_SESSION_HANDLE, phObject: c.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount: c.CK_ULONG, pulObjectCount: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_FindObjects, "C_FindObjects");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

export fn C_FindObjectsFinal(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_FindObjectsFinal, "C_FindObjectsFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

//usCount c.CK_USHORT (v1.0)
export fn C_FindObjectsInit(hSession: c.CK_SESSION_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_FindObjectsInit, "C_FindObjectsInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pTemplate, ulCount);
}

//usCount c.CK_USHORT (v1.0)
export fn C_GenerateKey(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG, phKey: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GenerateKey, "C_GenerateKey");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, pTemplate, ulCount, phKey);
}

//usPublicKeyAttributeCount c.CK_USHORT (v1.0)
//usPrivateKeyAttributeCount c.CK_USHORT (v1.0)
export fn C_GenerateKeyPair(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, pPublicKeyTemplate: c.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount: c.CK_ULONG, pPrivateKeyTemplate: c.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount: c.CK_ULONG, phPrivateKey: c.CK_OBJECT_HANDLE_PTR, phPublicKey: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GenerateKeyPair, "C_GenerateKeyPair");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPrivateKey, phPublicKey);
}

//usRandomLen c.CK_USHORT (v1.0)
export fn C_GenerateRandom(hSession: c.CK_SESSION_HANDLE, pRandomData: c.CK_BYTE_PTR, ulRandomLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GenerateRandom, "C_GenerateRandom");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pRandomData, ulRandomLen);
}

//usCount c.CK_USHORT (v1.0)
export fn C_GetAttributeValue(hSession: c.CK_SESSION_HANDLE, hObject: c.CK_OBJECT_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetAttributeValue, "C_GetAttributeValue");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hObject, pTemplate, ulCount);
}

export fn C_GetFunctionList(ppFunctionList: ?*?*c.CK_FUNCTION_LIST) c.CK_RV { // Since v2.0
    if (ppFunctionList == null) {
        log("Function list pointer cannot be null.\n", .{});
        return c.CKR_ARGUMENTS_BAD;
    }

    ppFunctionList.?.* = &functionList;

    return c.CKR_OK;
}

export fn C_GetFunctionStatus(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetFunctionStatus, "C_GetFunctionStatus");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_GetInfo(pInfo: c.CK_INFO_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetInfo, "C_GetInfo");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(pInfo);
}

export fn C_GetInterface(pInterfaceName: c.CK_UTF8CHAR_PTR, pVersion: c.CK_VERSION_PTR, ppInterface: c.CK_INTERFACE_PTR_PTR, flags: c.CK_FLAGS) c.CK_RV { // Since v3.0
    log("Function called: C_GetInterface(pInterfaceName={*}, pVersion={*}, ppInterface={*}, flags={})\n", .{ pInterfaceName, pVersion, ppInterface, flags });

    var matchingInterface: c.CK_INTERFACE_PTR = null;

    for (interfaces) |interfaceItem| {
        var interfaceNameMatches: bool = false;
        var versionMatches: bool = false;
        var flagMatches: bool = false;

        if (pInterfaceName == null) {
            interfaceNameMatches = true;
        } else {
            const interfaceName = interfaceItem.pInterfaceName;
            interfaceNameMatches = pInterfaceName.* == interfaceName.*;
        }
        if (pVersion == null) {
            versionMatches = true;
        } else {
            const version: *c.CK_VERSION = @ptrCast(@alignCast(interfaceItem.pFunctionList));
            versionMatches = (pVersion.*).major == version.major and (pVersion.*).minor == version.minor;
        }
        if (flags == 0x0) {
            flagMatches = true;
        } else {
            flagMatches = flags == interfaceItem.flags;
        }

        if (interfaceNameMatches and versionMatches and flagMatches) {
            matchingInterface = @constCast(&interfaceItem);
            break;
        }
    }

    if (matchingInterface != null) {
        ppInterface.* = matchingInterface;
        return c.CKR_OK;
    }
    return c.CKR_ARGUMENTS_BAD;
}

export fn C_GetInterfaceList(pInterfaceList: c.CK_INTERFACE_PTR, pulCount: c.CK_ULONG_PTR) c.CK_RV { // Since v3.0
    log("Function called: C_GetInterfaceList(pInterfaceList={*}, pulCount={*})\n", .{ pInterfaceList, pulCount });

    if (pulCount == null) {
        return c.CKR_ARGUMENTS_BAD;
    }

    const INTERFACE_COUNT = interfaces.len;

    if (pInterfaceList == null) {
        pulCount.* = INTERFACE_COUNT;
        return c.CKR_OK;
    }

    const CK_INTERFACE_SIZE = @sizeOf(c.CK_INTERFACE);
    pulCount.* = INTERFACE_COUNT;

    const dest_slice = @as([*]c.CK_INTERFACE, @ptrCast(pInterfaceList))[0..INTERFACE_COUNT];
    if (dest_slice.len < INTERFACE_COUNT * CK_INTERFACE_SIZE) {
        return c.CKR_BUFFER_TOO_SMALL;
    }

    @memcpy(dest_slice, &interfaces);

    return c.CKR_OK;
}

export fn C_GetMechanismInfo(slotID: c.CK_SLOT_ID, _type: c.CK_MECHANISM_TYPE, pInfo: c.CK_MECHANISM_INFO_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetMechanismInfo, "C_GetMechanismInfo");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, _type, pInfo);
}

//pusCount c.CK_USHORT_PTR (v1.0)
export fn C_GetMechanismList(slotID: c.CK_SLOT_ID, pMechanismList: c.CK_MECHANISM_TYPE_PTR, pulCount: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetMechanismList, "C_GetMechanismList");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, pMechanismList, pulCount);
}

//pusSize c.CK_USHORT_PTR (v1.0)
export fn C_GetObjectSize(hSession: c.CK_SESSION_HANDLE, hObject: c.CK_OBJECT_HANDLE, pulSize: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetObjectSize, "C_GetObjectSize");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hObject, pulSize);
}

export fn C_GetOperationState(hSession: c.CK_SESSION_HANDLE, pOperationState: c.CK_BYTE_PTR, pulOperationStateLen: c.CK_ULONG_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_GetOperationState, "C_GetOperationState");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pOperationState, pulOperationStateLen);
}

export fn C_GetSessionInfo(hSession: c.CK_SESSION_HANDLE, pInfo: c.CK_SESSION_INFO_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetSessionInfo, "C_GetSessionInfo");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pInfo);
}

export fn C_GetSlotInfo(slotID: c.CK_SLOT_ID, pInfo: c.CK_SLOT_INFO_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetSlotInfo, "C_GetSlotInfo");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, pInfo);
}

//pusCount c.CK_USHORT_PTR (v1.0)
export fn C_GetSlotList(tokenPresent: c.CK_BBOOL, pSlotList: c.CK_SLOT_ID_PTR, pulCount: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetSlotList, "C_GetSlotList");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(tokenPresent, pSlotList, pulCount);
}

export fn C_GetTokenInfo(slotID: c.CK_SLOT_ID, pInfo: c.CK_TOKEN_INFO_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_GetTokenInfo, "C_GetTokenInfo");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, pInfo);
}

//pReserved: c.CK_VOID_PTR (v1.0,v2.0)
export fn C_Initialize(pInitArgs: c.CK_VOID_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Initialize, "C_Initialize");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(pInitArgs);
}

//pPin c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
//usPinLen c.CK_USHORT (v1.0)
export fn C_InitPIN(hSession: c.CK_SESSION_HANDLE, pPin: c.CK_UTF8CHAR_PTR, ulPinLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_InitPIN, "C_InitPIN");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPin, ulPinLen);
}

//pPin c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
//usPinLen c.CK_USHORT (v1.0)
//pLabel c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
export fn C_InitToken(slotID: c.CK_SLOT_ID, pPin: c.CK_UTF8CHAR_PTR, ulPinLen: c.CK_ULONG, pLabel: c.CK_UTF8CHAR_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_InitToken, "C_InitToken");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, pPin, ulPinLen, pLabel);
}

//pPin c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
//usPinLen c.CK_USHORT (v1.0)
export fn C_Login(hSession: c.CK_SESSION_HANDLE, userType: c.CK_USER_TYPE, pPin: c.CK_UTF8CHAR_PTR, ulPinLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Login, "C_Login");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, userType, pPin, ulPinLen);
}

export fn C_LoginUser(hSession: c.CK_SESSION_HANDLE, userType: c.CK_USER_TYPE, pPin: c.CK_UTF8CHAR_PTR, ulPinLen: c.CK_ULONG, pUsername: c.CK_UTF8CHAR_PTR, ulUsernameLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_LoginUser, "C_LoginUser");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen);
}

export fn C_Logout(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Logout, "C_Logout");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_MessageDecryptFinal(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageDecryptFinal, "C_MessageDecryptFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_MessageDecryptInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageDecryptInit, "C_MessageDecryptInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_MessageEncryptFinal(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageEncryptFinal, "C_MessageEncryptFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_MessageEncryptInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageEncryptInit, "C_MessageEncryptInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_MessageSignFinal(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageSignFinal, "C_MessageSignFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_MessageSignInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageSignInit, "C_MessageSignInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_MessageVerifyFinal(hSession: c.CK_SESSION_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageVerifyFinal, "C_MessageVerifyFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession);
}

export fn C_MessageVerifyInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_MessageVerifyInit, "C_MessageVerifyInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

//CK_RV (*Notify)(CK_SESSION_HANDLE hSession, c.CK_NOTIFICATION event,: c.CK_VOID_PTR pApplication) (v1.0)
export fn C_OpenSession(slotID: c.CK_SLOT_ID, flags: c.CK_FLAGS, pApplication: c.CK_VOID_PTR, Notify: c.CK_NOTIFY, phSession: c.CK_SESSION_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_OpenSession, "C_OpenSession");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(slotID, flags, pApplication, Notify, phSession);
}

//usSeedLen c.CK_USHORT (v1.0)
export fn C_SeedRandom(hSession: c.CK_SESSION_HANDLE, pSeed: c.CK_BYTE_PTR, ulSeedLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SeedRandom, "C_SeedRandom");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pSeed, ulSeedLen);
}

export fn C_SessionCancel(hSession: c.CK_SESSION_HANDLE, flags: c.CK_FLAGS) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_SessionCancel, "C_SessionCancel");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, flags);
}

//usCount c.CK_USHORT (v1.0)
export fn C_SetAttributeValue(hSession: c.CK_SESSION_HANDLE, hObject: c.CK_OBJECT_HANDLE, pTemplate: c.CK_ATTRIBUTE_PTR, ulCount: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SetAttributeValue, "C_SetAttributeValue");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, hObject, pTemplate, ulCount);
}

export fn C_SetOperationState(hSession: c.CK_SESSION_HANDLE, pOperationState: c.CK_BYTE_PTR, ulOperationStateLen: c.CK_ULONG, hEncryptionKey: c.CK_OBJECT_HANDLE, hAuthenticationKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_SetOperationState, "C_SetOperationState");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}

//pOldPin c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
//usOldLen c.CK_USHORT (v1.0)
//pNewPin c.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)
//usNewLen c.CK_USHORT (v1.0)
export fn C_SetPIN(hSession: c.CK_SESSION_HANDLE, pOldPin: c.CK_UTF8CHAR_PTR, ulOldLen: c.CK_ULONG, pNewPin: c.CK_UTF8CHAR_PTR, ulNewLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SetPIN, "C_SetPIN");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}

//usDataLen c.CK_USHORT (v1.0)
//pusSignatureLen c.CK_USHORT_PTR (v1.0)
export fn C_Sign(hSession: c.CK_SESSION_HANDLE, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, pulSignatureLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Sign, "C_Sign");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

export fn C_SignEncryptUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG, pEncryptedPart: c.CK_BYTE_PTR, pulEncryptedPartLen: c.CK_ULONG_PTR) c.CK_RV { // Since v2.0
    const function = getDynamicLibraryFunction(c.CK_C_SignEncryptUpdate, "C_SignEncryptUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

//pusSignatureLen c.CK_USHORT_PTR (v1.0)
export fn C_SignFinal(hSession: c.CK_SESSION_HANDLE, pSignature: c.CK_BYTE_PTR, pulSignatureLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SignFinal, "C_SignFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pSignature, pulSignatureLen);
}

export fn C_SignInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SignInit, "C_SignInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_SignMessage(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, pulSignatureLen: c.CK_ULONG_PTR) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_SignMessage, "C_SignMessage");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, pulSignatureLen);
}

export fn C_SignMessageBegin(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_SignMessageBegin, "C_SignMessageBegin");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen);
}

export fn C_SignMessageNext(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pDataPart: c.CK_BYTE_PTR, ulDataPartLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, pulSignatureLen: c.CK_ULONG_PTR) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_SignMessageNext, "C_SignMessageNext");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, pulSignatureLen);
}

//usDataLen c.CK_USHORT (v1.0)
//pusSignatureLen c.CK_USHORT_PTR (v1.0)
export fn C_SignRecover(hSession: c.CK_SESSION_HANDLE, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, pulSignatureLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SignRecover, "C_SignRecover");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

export fn C_SignRecoverInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SignRecoverInit, "C_SignRecoverInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

//usPartLen c.CK_USHORT (v1.0)
export fn C_SignUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_SignUpdate, "C_SignUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen);
}

//usWrappedKeyLen c.CK_USHORT (v1.0)
//usAttributeCount c.CK_USHORT (v1.0)
export fn C_UnwrapKey(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hUnwrappingKey: c.CK_OBJECT_HANDLE, pWrappedKey: c.CK_BYTE_PTR, ulWrappedKeyLen: c.CK_ULONG, pTemplate: c.CK_ATTRIBUTE_PTR, ulAttributeCount: c.CK_ULONG, phKey: c.CK_OBJECT_HANDLE_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_UnwrapKey, "C_UnwrapKey");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
}

//usDataLen c.CK_USHORT (v1.0)
//usSignatureLen c.CK_USHORT (v1.0)
export fn C_Verify(hSession: c.CK_SESSION_HANDLE, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, ulSignatureLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_Verify, "C_Verify");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

//usSignatureLen c.CK_USHORT_PTR (v1.0)
export fn C_VerifyFinal(hSession: c.CK_SESSION_HANDLE, pSignature: c.CK_BYTE_PTR, ulSignatureLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyFinal, "C_VerifyFinal");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pSignature, ulSignatureLen);
}

export fn C_VerifyInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyInit, "C_VerifyInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

export fn C_VerifyMessage(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pData: c.CK_BYTE_PTR, ulDataLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, ulSignatureLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyMessage, "C_VerifyMessage");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pData, ulDataLen, pSignature, ulSignatureLen);
}

export fn C_VerifyMessageBegin(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyMessageBegin, "C_VerifyMessageBegin");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen);
}

export fn C_VerifyMessageNext(hSession: c.CK_SESSION_HANDLE, pParameter: c.CK_VOID_PTR, ulParameterLen: c.CK_ULONG, pDataPart: c.CK_BYTE_PTR, ulDataPartLen: c.CK_ULONG, pSignature: c.CK_BYTE_PTR, ulSignatureLen: c.CK_ULONG) c.CK_RV { // Since v3.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyMessageNext, "C_VerifyMessageNext");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, ulSignatureLen);
}

//usSignatureLen c.CK_USHORT (v1.0)
//pusDataLen c.CK_USHORT_PTR (v1.0)
export fn C_VerifyRecover(hSession: c.CK_SESSION_HANDLE, pSignature: c.CK_BYTE_PTR, ulSignatureLen: c.CK_ULONG, pData: c.CK_BYTE_PTR, pulDataLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyRecover, "C_VerifyRecover");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}

export fn C_VerifyRecoverInit(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hKey: c.CK_OBJECT_HANDLE) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyRecoverInit, "C_VerifyRecoverInit");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hKey);
}

//usPartLen c.CK_USHORT (v1.0)
export fn C_VerifyUpdate(hSession: c.CK_SESSION_HANDLE, pPart: c.CK_BYTE_PTR, ulPartLen: c.CK_ULONG) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_VerifyUpdate, "C_VerifyUpdate");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pPart, ulPartLen);
}

export fn C_WaitForSlotEvent(flags: c.CK_FLAGS, pSlot: c.CK_SLOT_ID_PTR, pReserved: c.CK_VOID_PTR) c.CK_RV { // Since v2.01
    const function = getDynamicLibraryFunction(c.CK_C_WaitForSlotEvent, "C_WaitForSlotEvent");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(flags, pSlot, pReserved);
}

//pusWrappedKeyLen c.CK_USHORT_PTR (v1.0)
export fn C_WrapKey(hSession: c.CK_SESSION_HANDLE, pMechanism: c.CK_MECHANISM_PTR, hWrappingKey: c.CK_OBJECT_HANDLE, hKey: c.CK_OBJECT_HANDLE, pWrappedKey: c.CK_BYTE_PTR, pulWrappedKeyLen: c.CK_ULONG_PTR) c.CK_RV { // Since v1.0
    const function = getDynamicLibraryFunction(c.CK_C_WrapKey, "C_WrapKey");
    if (function == null) {
        log("Failed getting symbol for this function.\n", .{});
        return c.CKR_FUNCTION_NOT_SUPPORTED;
    }

    return function.?(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
}
