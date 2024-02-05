
rule Trojan_BAT_Formbook_PFA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 16 0c 02 00 0b 90 02 06 06 07 20 00 01 00 00 28 90 01 03 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 90 02 17 74 90 01 03 01 72 90 01 03 70 6f 90 01 03 0a 80 90 01 03 04 2a 90 00 } //01 00 
		$a_03_1 = {0a 06 72 55 16 00 70 20 00 01 00 00 14 14 17 8d 90 01 03 01 25 16 02 a2 6f 90 01 03 0a 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}