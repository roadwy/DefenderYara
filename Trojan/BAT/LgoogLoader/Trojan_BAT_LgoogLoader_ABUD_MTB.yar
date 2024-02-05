
rule Trojan_BAT_LgoogLoader_ABUD_MTB{
	meta:
		description = "Trojan:BAT/LgoogLoader.ABUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 06 03 6f 90 01 01 00 00 0a 0b 00 07 6f 90 01 01 00 00 0a 0c 00 02 08 28 90 01 01 00 00 06 0d de 16 08 2c 07 08 6f 90 01 01 00 00 0a 00 dc 90 00 } //02 00 
		$a_03_1 = {07 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 07 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0c de 16 07 2c 07 07 6f 90 01 01 00 00 0a 00 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}