
rule Trojan_Win64_Icedid_E_MTB{
	meta:
		description = "Trojan:Win64/Icedid.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b c2 48 8d 49 01 83 e0 03 ff c2 0f b6 44 30 2c 30 41 ff 3b d7 72 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_E_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b d2 d6 89 d1 81 c1 34 08 00 00 48 63 c9 48 69 c9 09 04 02 81 48 c1 e9 20 01 d1 81 c1 34 08 00 00 89 c8 c1 e8 1f c1 f9 06 01 c1 89 c8 c1 e0 07 29 c1 8d 04 0a 05 34 08 00 00 01 d1 81 c1 b3 08 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}