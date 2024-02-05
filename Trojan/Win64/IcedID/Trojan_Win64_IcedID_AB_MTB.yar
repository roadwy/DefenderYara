
rule Trojan_Win64_IcedID_AB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 89 84 24 90 01 04 e9 90 01 04 8b 4c 24 90 01 01 33 c8 3a db 74 90 00 } //01 00 
		$a_03_1 = {8b c1 48 63 4c 24 90 01 01 66 3b f6 0f 84 90 01 04 48 f7 f1 48 8b c2 3a d2 74 90 01 01 48 90 01 04 48 90 01 07 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 66 90 01 02 90 13 33 d2 48 8b c1 b9 08 00 00 00 90 01 03 90 13 48 f7 f1 48 8b c2 48 8b 4c 24 48 3a 90 01 01 90 13 0f b6 44 01 90 01 01 8b 4c 24 68 33 c8 3a 90 01 01 74 90 00 } //01 00 
		$a_03_1 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 3a 90 01 01 90 13 33 d2 48 8b c1 b9 08 00 00 00 90 01 02 90 13 48 f7 f1 48 8b c2 48 8b 4c 24 48 66 3b 90 01 01 90 13 0f b6 44 01 90 01 01 8b 4c 24 68 33 c8 66 3b 90 00 } //01 00 
		$a_03_2 = {8b c1 48 63 4c 24 44 48 8b 54 24 58 90 13 88 04 0a 90 13 8b 44 24 44 90 13 ff c0 89 44 24 44 8b 84 24 98 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}