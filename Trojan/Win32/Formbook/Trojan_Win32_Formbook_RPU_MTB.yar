
rule Trojan_Win32_Formbook_RPU_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 39 04 90 01 01 34 90 01 01 2c 90 01 01 34 90 01 01 fe c8 88 04 39 41 3b cb 72 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RPU_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 f3 bd 00 00 81 fa ef 44 00 00 74 0c bb 76 d6 00 00 40 49 35 fe d7 00 00 c2 a8 07 81 c2 1b 1d 00 00 c2 19 f5 5a 81 c1 45 85 00 00 c2 98 4c c2 18 85 25 f9 5e 00 00 f7 d1 49 } //00 00 
	condition:
		any of ($a_*)
 
}