
rule Trojan_Win32_Formbook_RPE_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 0c 5e f7 fe 8a 82 90 01 04 30 04 19 41 3b cf 72 ea 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Formbook_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 19 04 90 01 01 34 90 01 01 04 90 01 01 88 04 19 41 3b cf 72 ef 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}