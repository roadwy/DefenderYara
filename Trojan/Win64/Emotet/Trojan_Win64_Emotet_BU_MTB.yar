
rule Trojan_Win64_Emotet_BU_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 03 d1 41 ff c1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 13 90 01 01 41 88 4a 90 01 01 48 ff cb 74 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_BU_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 ef c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c7 ff c7 6b d2 90 01 01 2b c2 48 98 32 0c 18 4c 3b e6 41 88 4c 2c ff 7d 90 00 } //02 00 
		$a_03_1 = {f7 ef d1 fa 8b c2 c1 e8 90 01 01 03 d0 8b c7 ff c7 6b d2 90 01 01 2b c2 48 98 42 32 0c 90 01 01 48 3b f3 42 88 4c 1e ff 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}