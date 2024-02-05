
rule Trojan_Win64_Dridex_GZ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 41 b8 08 00 00 00 a8 01 74 90 01 01 d1 e8 35 20 83 b8 ed eb 90 01 01 d1 e8 49 83 e8 01 75 90 01 01 89 02 ff c1 48 83 c2 04 81 f9 00 01 00 00 7c 90 01 01 48 85 f6 7e 90 01 01 0f b6 0c 2f 90 00 } //01 00 
		$a_02_1 = {41 8a 0a 8d 41 9f 3c 19 77 90 01 01 80 c1 e0 41 88 08 84 c9 74 90 01 01 0f b7 43 58 41 ff c1 49 83 c2 02 49 ff c0 41 ff c3 44 3b c8 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_GZ_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 ca 8b 4c 24 90 01 01 83 f1 ff 4c 8b 84 24 90 02 04 89 8c 24 90 02 04 4c 8b 4c 24 90 01 01 4c 29 c2 4c 8b 44 24 90 01 01 49 81 f0 90 02 04 4c 89 44 24 90 01 01 4d 89 c8 49 21 d0 90 00 } //0a 00 
		$a_02_1 = {4c 8b 44 24 90 01 01 47 88 1c 08 66 8b 74 24 90 01 01 66 89 74 24 90 01 01 48 8b 7c 24 90 01 01 49 01 d1 66 69 74 24 90 01 03 66 89 74 24 90 01 01 4c 89 4c 24 90 01 01 49 39 f9 0f 84 90 01 04 e9 90 00 } //01 00 
		$a_80_2 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  01 00 
		$a_80_3 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  00 00 
	condition:
		any of ($a_*)
 
}