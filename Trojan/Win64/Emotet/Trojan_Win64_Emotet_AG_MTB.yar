
rule Trojan_Win64_Emotet_AG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b cb f7 eb ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 35 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_AG_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b cf f7 ef ff c7 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 37 2b c8 48 8b 05 90 01 04 48 63 d1 0f b6 0c 02 41 32 0c 36 88 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}