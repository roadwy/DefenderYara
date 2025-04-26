
rule TrojanDownloader_Win32_Bandit_MS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bandit.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c1 ea ?? 03 cb 03 55 ?? 33 d1 33 d6 2b fa 89 7d ?? 3d ?? ?? ?? ?? 75 } //2
		$a_00_1 = {c7 45 f8 20 37 ef c6 } //1
		$a_00_2 = {81 c1 47 86 c8 61 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}