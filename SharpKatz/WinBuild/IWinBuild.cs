using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpKatz.WinBuild
{
    interface IWinBuild
    {
        int build { get; set; }
        Type PrimaryCredentialsType { get; set; }
        Type PrimaryCredentialType { get; set; }
        Type ListType { get; set; }
        Type LogonSessionType { get; set; }
        Type KerberosPrimaryCredentialType { get; set; }
        Type TSCredType { get; set; }
        Type KerberosLogonSessionType { get; set; }
        Type KerberosHashType { get; set; }
        int LOGONSESSIONLISTOFFSET { get; set; }
        int LOGONSESSIONSLISTCOUNTOFFSET { get; set; }
        byte[] logonSessionListSign { get; set; }
        long IV_OFFSET { get; set; }
        long DES_OFFSET { get; set; }
        long AES_OFFSET { get; set; }
        byte[] keyIVSig { get; set; }
        byte[] logSessListSig { get; set; }
        int ListTypeSize { get; set; }
        int LogonSessionTypeSize { get; set; }
        byte[] SspCredentialListSign { get; set; }
        int CREDENTIALLISTOFFSET { get; set; }
        byte[] LiveLocateLogonSession { get; set; }
        int LIVESSPLISTOFFSET { get; set; }
        byte[] KerbUnloadLogonSessionTableSign { get; set; }
        int KerbUnloadLogonSessionTableOffset { get; set; }
        byte[] TSGlobalCredTableSign { get; set; }
        int TSGlobalCredTableOffset { get; set; }
        int KerberosPrimaryCredentialTypeSize { get; set; }

    }
}
