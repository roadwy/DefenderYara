
rule Trojan_BAT_Rozena_JSAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.JSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 13 07 7e 90 01 01 00 00 0a 11 07 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 13 08 11 07 16 11 08 11 07 8e 69 28 90 01 01 00 00 0a 11 08 11 07 8e 69 1f 20 12 09 28 90 01 01 00 00 06 26 7e 90 01 01 00 00 0a 26 16 13 0a 7e 90 01 01 00 00 0a 16 11 08 7e 90 01 01 00 00 0a 16 12 0a 28 90 01 01 00 00 06 15 28 90 01 01 00 00 06 26 de 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}