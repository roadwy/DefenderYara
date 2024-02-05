
rule Trojan_Win32_Farfli_GKM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 10 80 f2 3d 80 c2 3d 88 10 83 c0 01 83 e9 01 75 } //01 00 
		$a_02_1 = {8b f8 8b 46 90 01 01 03 44 24 90 01 01 52 50 57 e8 90 01 04 89 7e 90 01 01 83 c4 0c 8b 4c 24 90 01 01 8b 11 8b 44 24 90 01 01 0f b7 4a 90 01 01 83 c0 01 83 c6 28 3b c1 89 44 24 90 01 01 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}