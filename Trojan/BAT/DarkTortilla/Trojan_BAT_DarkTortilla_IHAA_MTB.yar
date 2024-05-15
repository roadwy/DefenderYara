
rule Trojan_BAT_DarkTortilla_IHAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.IHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 00 09 07 6f 90 01 01 00 00 0a 00 09 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 05 00 11 05 13 06 00 73 90 01 01 00 00 0a 13 07 00 11 07 11 06 17 73 90 01 01 00 00 0a 13 08 11 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 11 08 6f 90 01 01 00 00 0a 00 11 07 6f 90 01 01 00 00 0a 0c de 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}