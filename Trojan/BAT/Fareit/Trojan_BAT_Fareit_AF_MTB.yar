
rule Trojan_BAT_Fareit_AF_MTB{
	meta:
		description = "Trojan:BAT/Fareit.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 6f 11 00 00 0a 6f 12 00 00 0a 0b 07 2c 1c 28 13 00 00 0a 72 69 00 00 70 28 14 00 00 0a 25 07 28 15 00 00 0a 28 16 00 00 0a 26 de 0a 06 2c 06 06 } //00 00 
	condition:
		any of ($a_*)
 
}