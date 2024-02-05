
rule Backdoor_Win64_CobaltStrikeLoader_HCC_dha{
	meta:
		description = "Backdoor:Win64/CobaltStrikeLoader.HCC!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 89 c0 e8 6a 00 00 00 48 3d f0 49 12 00 74 04 } //01 00 
		$a_01_1 = {48 6b d2 0a 48 0f b6 08 48 83 e9 30 48 ff c0 48 01 ca 80 38 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}