
rule Trojan_Win64_Emotet_PBF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 8b 0d 90 01 04 0f af 0d 90 01 04 8b 14 24 2b d1 8b ca 8b 15 90 01 04 0f af 15 90 01 04 03 ca 90 02 60 48 63 c9 48 8b 54 24 28 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_PBF_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ef ff c7 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 48 8d 0d 90 02 04 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}