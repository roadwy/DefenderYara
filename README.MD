
# DefenderYara


![DefenderYara](https://socialify.git.ci/roadwy/DefenderYara/image?description=1&font=Inter&forks=1&issues=1&language=1&owner=1&pattern=Plus&stargazers=1&theme=Light)

## Description
Extracted Yara rules from Defender mpavbase.vdm and mpasbase.Enjoy it.

```YARA
rule HackTool_Win64_ATPMiniDump_lsa{
	meta:
		description = "HackTool:Win64/ATPMiniDump!lsa,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 54 50 4d 69 6e 69 44 75 6d 70 } //2 ATPMiniDump
		$a_01_1 = {42 00 79 00 20 00 62 00 34 00 72 00 74 00 69 00 6b 00 20 00 26 00 20 00 75 00 66 00 30 00 } //2 By b4rtik & uf0
		$a_01_2 = {54 00 65 00 6d 00 70 00 5c 00 64 00 75 00 6d 00 70 00 65 00 72 00 74 00 2e 00 64 00 6d 00 70 00 } //2 Temp\dumpert.dmp
		$a_01_3 = {5b 00 21 00 5d 00 20 00 59 00 6f 00 75 00 20 00 6e 00 65 00 65 00 64 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 } //1 [!] You need elevated
		$a_01_4 = {5b 00 21 00 5d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 6d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00 2c 00 } //1 [!] Failed to create minidump,
		$a_01_5 = {5b 00 31 00 5d 00 20 00 43 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 20 00 4f 00 53 00 } //1 [1] Checking OS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
```
NOTE: some strings or condition maybe wrong. 

Parsed HSTR type:
- SIGNATURE_TYPE_PEHSTR_EXT
- SIGNATURE_TYPE_ELFHSTR_EXT
- SIGNATURE_TYPE_MACHOHSTR_EXT
- SIGNATURE_TYPE_MACROHSTR_EXT
- SIGNATURE_TYPE_DEXHSTR_EXT
- SIGNATURE_TYPE_JAVAHSTR_EXT
- SIGNATURE_TYPE_CMDHSTR_EXT
- SIGNATURE_TYPE_ARHSTR_EXT
- SIGNATURE_TYPE_PEHSTR

TODO:
- SIGNATURE_TYPE_SWFHSTR_EXT
- SIGNATURE_TYPE_AUTOITHSTR_EXT
- SIGNATURE_TYPE_INNOHSTR_EXT
- SIGNATURE_TYPE_MDBHSTR_EXT
- SIGNATURE_TYPE_DMGHSTR_EXT

## Reference
- https://github.com/commial/experiments/tree/master/windows-defender
- https://github.com/HackingLZ/ExtractedDefender
- https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/malware-naming?view=o365-worldwide
- https://github.com/t0-retooling/defender-recon24/