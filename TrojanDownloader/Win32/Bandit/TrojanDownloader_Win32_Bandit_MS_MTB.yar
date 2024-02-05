
rule TrojanDownloader_Win32_Bandit_MS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bandit.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b d3 c7 05 90 01 08 c1 ea 90 01 01 03 cb 03 55 90 01 01 33 d1 33 d6 2b fa 89 7d 90 01 01 3d 90 01 04 75 90 00 } //01 00 
		$a_00_1 = {c7 45 f8 20 37 ef c6 } //01 00 
		$a_00_2 = {81 c1 47 86 c8 61 } //00 00 
	condition:
		any of ($a_*)
 
}