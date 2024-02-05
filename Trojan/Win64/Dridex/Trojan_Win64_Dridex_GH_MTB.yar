
rule Trojan_Win64_Dridex_GH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 83 ec 40 8b 44 24 3c 89 ca 09 c2 89 54 24 3c 48 c7 44 24 28 3a 51 d7 3d 4c 8b } //01 00 
		$a_00_1 = {a0 37 b7 8d b9 8f } //01 00 
		$a_00_2 = {9d 51 71 af a7 } //01 00 
		$a_02_3 = {e5 44 15 de 71 f2 89 90 01 02 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GH_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {88 d8 41 f6 e2 88 84 24 0d 01 00 00 89 4c 24 90 01 01 4c 89 c1 44 8b 44 24 90 01 01 e8 90 01 04 48 8b 8c 24 d0 00 00 00 e8 90 00 } //0a 00 
		$a_02_1 = {4c 89 f2 44 8b 5c 24 90 01 01 44 89 44 24 90 01 01 45 89 d8 8b 6c 24 90 01 01 44 89 4c 24 90 01 01 41 89 e9 48 89 7c 24 90 01 01 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}