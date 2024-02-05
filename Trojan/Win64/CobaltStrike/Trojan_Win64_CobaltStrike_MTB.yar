
rule Trojan_Win64_CobaltStrike_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8b 40 08 48 2b c1 48 c1 f8 05 48 83 c4 18 } //01 00 
		$a_01_1 = {48 89 4c 24 08 48 83 ec 38 48 8b 44 24 40 48 83 c8 0f 48 89 44 24 20 48 8b 44 24 } //01 00 
		$a_01_2 = {48 89 4c 24 08 48 83 ec 18 48 8b 44 24 20 48 89 04 24 48 6b 44 24 28 20 48 8b 0c 24 48 03 01 48 83 c4 18 } //01 00 
		$a_01_3 = {48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff } //01 00 
		$a_01_4 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a 40 b0 1d 00 4d 03 da } //01 00 
		$a_01_5 = {49 81 f8 80 00 00 00 0f 86 8e 00 00 00 4c 8b c9 49 83 e1 0f 49 83 e9 10 49 2b c9 49 2b d1 4d 03 c1 49 81 f8 80 } //00 00 
	condition:
		any of ($a_*)
 
}