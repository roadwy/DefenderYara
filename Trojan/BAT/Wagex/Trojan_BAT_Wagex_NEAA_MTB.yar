
rule Trojan_BAT_Wagex_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Wagex.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 2b 00 07 09 6f 90 01 01 00 00 0a 13 04 06 11 04 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 0c 06 6f 90 01 01 00 00 0a 08 16 08 8e 69 6f 90 01 01 00 00 0a 13 05 de 0e 90 00 } //0a 00 
		$a_03_1 = {1b 2d 1c 26 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2b 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}