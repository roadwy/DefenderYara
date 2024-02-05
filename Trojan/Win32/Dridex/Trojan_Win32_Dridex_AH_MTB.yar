
rule Trojan_Win32_Dridex_AH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 04 dd 00 00 00 00 2b c3 03 c0 03 c0 0f b7 c0 8a 0d 90 01 04 2a c8 80 e9 4c 02 d1 66 0f b6 c2 66 03 c3 66 83 c0 09 0f b7 c8 8b 06 90 00 } //0a 00 
		$a_00_1 = {02 c1 2c 61 02 d0 83 c6 04 83 ef 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8d 14 01 8d 7c 17 17 8b d0 2b d1 03 d3 8d 0c 12 81 c6 94 3c 0a 01 8b d7 89 75 00 2b d1 } //0a 00 
		$a_02_1 = {8b c1 6b c9 05 2b c6 83 c0 2c 03 ca 0f b7 15 90 01 04 8b 75 00 2b d7 03 15 90 01 04 8d 9c 01 d0 55 00 00 8b fa 8b d3 6b d2 05 03 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AH_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {70 72 6f 70 65 72 74 79 5f 53 74 69 6c 6c 5c 68 65 72 2e 70 64 62 } //property_Still\her.pdb  03 00 
		$a_80_1 = {4d 6f 64 65 72 6e 6d 61 6a 6f 72 } //Modernmajor  03 00 
		$a_80_2 = {4d 65 52 65 71 75 69 72 65 } //MeRequire  03 00 
		$a_80_3 = {49 4e 46 5f 63 72 63 64 69 73 6b } //INF_crcdisk  03 00 
		$a_80_4 = {49 4e 46 5f 77 75 64 66 75 73 62 63 63 69 64 64 72 69 76 65 72 } //INF_wudfusbcciddriver  03 00 
		$a_80_5 = {68 65 72 2e 64 6c 6c } //her.dll  03 00 
		$a_80_6 = {72 65 36 77 6d 69 73 6c 75 } //re6wmislu  00 00 
	condition:
		any of ($a_*)
 
}