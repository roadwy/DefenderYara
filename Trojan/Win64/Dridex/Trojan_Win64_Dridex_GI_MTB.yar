
rule Trojan_Win64_Dridex_GI_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {45 31 c0 44 89 c1 44 8b 44 24 90 01 01 45 89 c1 44 89 ca 44 8b 44 24 90 01 01 44 8b 4c 24 90 01 01 ff d0 90 00 } //0a 00 
		$a_02_1 = {e6 2f 44 8b 84 24 90 02 04 44 8b 8c 24 90 02 04 41 81 c0 c7 a3 49 b0 44 29 c8 48 89 4c 24 60 89 44 24 5c e8 90 02 04 8b 84 24 90 02 04 05 b9 b3 49 b0 c6 84 24 90 02 04 90 01 01 48 8b 4c 24 90 01 01 89 44 24 90 01 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GI_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 29 f1 41 81 f3 30 1b e3 01 48 89 8c 24 90 01 04 8b bc 24 90 01 04 81 c7 cc f4 1c fe 4c 89 c9 41 89 c0 44 89 5c 24 90 01 01 89 7c 24 90 01 01 e8 90 01 04 8a 5c 24 90 01 01 80 c3 90 01 01 88 9c 24 90 01 04 48 8b 8c 24 90 01 04 e8 90 00 } //0a 00 
		$a_02_1 = {44 8b 9c 24 90 01 04 45 89 d9 66 c7 84 24 90 01 06 48 89 54 24 90 01 01 4c 89 ca 44 8b 5c 24 90 01 01 44 89 44 24 90 01 01 45 89 d8 44 8b 4c 24 90 01 01 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}