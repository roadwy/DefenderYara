
rule Trojan_Win64_Emotet_AK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 30 88 04 0a } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_Emotet_AK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 8c 24 fc 00 00 00 33 c8 8b c1 8b 4c 24 34 8b 54 24 30 2b d1 8b ca 03 4c 24 34 48 63 c9 48 8b 94 24 f0 00 00 00 88 04 0a } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_Emotet_AK_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 63 4c 24 04 0f b6 04 08 89 04 24 48 8b 4c 24 20 48 63 44 24 04 31 d2 48 f7 74 24 50 8b 04 24 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 10 48 63 4c 24 04 88 14 08 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}