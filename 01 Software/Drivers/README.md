# ***🧊 Affected Drivers***



---
---
---



## ***📦 Download Behavior***

Both Deep Freeze editions are available for download from the official Faronics website. The following was observed during research:

### ***🖥️ Standard Edition***

Downloading Deep Freeze Standard from the Faronics website installs version **9.00.020.5760**, with no update prompt or newer version offered.

### ***🏢 Enterprise Edition***

Downloading Deep Freeze Enterprise presents a **pop-up notification** indicating that a newer version is available - **10.10.220.5788**. The Enterprise installer then allows downloading the updated **Deep Freeze Enterprise Workstation** package at version 10.10.220.5788.



---
---
---



## ***✅ Vulnerability Verification***

The stack overflow vulnerability in `DfDiskLo.sys` has been confirmed in **both editions and both versions**:

| Edition                | Version        | DfDiskLo.sys | Vulnerable   |
|------------------------|----------------|--------------|--------------|
| Standard               | 9.00.020.5760  | Included     | ✅ Confirmed |
| Enterprise Workstation | 10.10.220.5788 | Included     | ✅ Confirmed |

```
Drivers/
	Standard_9.00.020.5760/
		DeepFrz.sys
		DfDiskLo.sys      <- vulnerable
		DFRegMon.sys
		FarDisk.sys
		FarSpace.sys

	Enterprise_10.10.220.5788/
		DeepFrz.sys
		DfDiskLo.sys      <- vulnerable
		DFRegMon.sys
		FarDisk.sys
		FarSpace.sys
```



---
---
---



## ***🔐 Driver Hash Verification***

The following SHA256 hashes correspond to the tested driver samples used during vulnerability verification.

### ***🖥️ Standard - 9.00.020.5760***

```powershell
PS> Get-FileHash .\DfDiskLo.sys -Algorithm SHA256
```

| Driver       | SHA256 |
|--------------|---------|
| DeepFrz.sys  | C4B9E841A6798A4740B1AA014B033A2E864DF665C1DB6B679F31BC8D77DBB73F |
| DfDiskLo.sys | 7261C1D4B36EDCAB3E1EB774A5E00E6D3E8C876AD62CF0E5CD9D1B6BF7D08819 |
| DFRegMon.sys | DE59B7956510F25012F7F89E1CB2E05A13E1DA6A0CAC93E4A3B025B30836FBD4 |
| FarDisk.sys  | 9F985A9F1A60880DB2D6820C4DABA548BAA371B4E6BE3F37DCCE84B5C6AA9E07 |
| FarSpace.sys | E765CB04BBF9836963B14977485B33F39725B3F668329AB5B57E9543F9B6D93D |

### ***🏢 Enterprise Workstation - 10.10.220.5788***

```powershell
PS> Get-FileHash .\DfDiskLo.sys -Algorithm SHA256
```

| Driver       | SHA256 |
|--------------|---------|
| DeepFrz.sys  | 2EDE844D9E2833228CF0EB16187120CA59864F8709EA4FA240FEC52B3AB224CF |
| DfDiskLo.sys | 93CF724A96435FB4AB6F2013F406C0097FA36E0105EF2A878AE4AA4EF3E13C5F |
| DFRegMon.sys | D920A6FAF6635F59C29FAB9F84B509F28F47621D07E457F5E122CD76C7FCBBD5 |
| FarDisk.sys  | DA0DDE139E5B310977B1BA0301A07CC68EE87DF19B7D8C94F5D3AA6109734DA9 |
| FarSpace.sys | 3D9E5CE4C289357F9945D0BED3F8DA3F6FEF58783888A5F093669C57F773883C |



---
---
---



## ***🔗 Download Sources***

| Edition    | URL |
|------------|-----|
| Standard   | https://www.faronics.com/products/deep-freeze/standard, https://www.faronics.com/es/downloads_es/download-files_es?product=DFS |
| Enterprise | https://www.faronics.com/products/deep-freeze/enterprise, https://www.faronics.com/es/downloads_es/download-files_es?product=DFE |
