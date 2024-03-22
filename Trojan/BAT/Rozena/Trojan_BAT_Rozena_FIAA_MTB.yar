
rule Trojan_BAT_Rozena_FIAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.FIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 16 06 8e 69 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 0c 06 16 08 6e 28 90 01 01 00 00 0a 06 8e 69 28 90 01 01 00 00 0a 7e 90 01 01 00 00 0a 26 16 0d 7e 90 01 01 00 00 0a 13 04 16 16 08 11 04 16 12 03 28 90 01 01 00 00 06 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}