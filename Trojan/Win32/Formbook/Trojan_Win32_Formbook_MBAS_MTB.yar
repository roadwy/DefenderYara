
rule Trojan_Win32_Formbook_MBAS_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 90 01 04 30 04 1e 46 3b f7 72 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_MBAS_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e6 c1 ea 03 8b c6 8d 0c 52 c1 e1 02 2b c1 46 8a 80 90 01 04 30 44 33 ff 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}