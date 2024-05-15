
rule Trojan_BAT_DarkTortilla_KIAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.KIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 8e 69 17 da 0a 16 0b 2b 16 07 1d 5d 16 fe 01 0c 08 2c 08 02 07 02 07 91 03 61 9c 07 17 d6 0b 07 06 31 e6 } //00 00 
	condition:
		any of ($a_*)
 
}