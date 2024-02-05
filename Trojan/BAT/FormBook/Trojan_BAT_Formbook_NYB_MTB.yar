
rule Trojan_BAT_Formbook_NYB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5a 1e 58 6a 58 6f 90 01 03 0a 05 6f 90 01 03 0a 0b 05 6f 90 01 03 0a 0c 05 6f 90 01 03 0a 26 05 6f 90 01 03 0a 0d 08 02 42 90 01 03 00 02 08 07 58 90 00 } //01 00 
		$a_01_1 = {38 33 2d 63 62 32 62 33 31 61 38 63 33 31 37 } //00 00 
	condition:
		any of ($a_*)
 
}