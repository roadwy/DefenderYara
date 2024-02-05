
rule Trojan_BAT_Formbook_PD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {16 0c 2b 1f 06 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 08 18 d6 0c 08 07 31 dd 06 6f 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_02_1 = {0a 16 9a 13 90 01 01 11 90 01 01 72 90 01 03 70 20 00 01 00 00 14 14 1a 8d 01 00 00 01 13 90 01 01 11 90 01 01 16 90 02 02 a2 11 90 01 01 17 90 02 02 a2 11 90 01 01 18 90 02 02 a2 11 90 02 0a 6f 90 01 01 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}