
rule Trojan_BAT_Formbook_RPZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 11 07 1e 62 08 11 08 6f 57 00 00 0a a5 14 00 00 01 60 13 09 08 11 08 11 09 1f 18 5b d2 8c 14 00 00 01 6f 58 00 00 0a 00 11 09 1f 18 5d 13 07 07 11 05 06 11 07 93 9d 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0a 11 0a 2d b3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 07 09 18 6f 90 00 00 0a 1f 10 28 91 00 00 0a 13 05 08 11 05 6f 92 00 00 0a 00 09 18 58 0d 00 09 07 6f 93 00 00 0a fe 04 13 06 11 06 2d d1 } //01 00 
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 } //01 00 
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 } //01 00 
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_RPZ_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 28 15 00 00 0a 00 00 02 23 00 00 00 00 00 88 d3 40 73 16 00 00 0a 7d 01 00 00 04 02 7b 01 00 00 04 02 fe 06 04 00 00 06 73 17 00 00 0a 6f 18 00 00 0a 00 02 7b 01 00 00 04 17 6f 19 00 00 0a 00 02 7b 01 00 00 04 16 6f 1a 00 00 0a 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}