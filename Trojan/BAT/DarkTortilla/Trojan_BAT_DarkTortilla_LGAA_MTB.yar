
rule Trojan_BAT_DarkTortilla_LGAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.LGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 08 11 08 74 90 01 01 00 00 01 02 74 90 01 01 00 00 1b 16 02 14 72 d3 03 00 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 08 75 90 01 01 00 00 01 6f 90 01 01 00 00 0a 11 07 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 0c de 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}