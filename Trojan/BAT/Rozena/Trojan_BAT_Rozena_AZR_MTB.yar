
rule Trojan_BAT_Rozena_AZR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 16 13 37 2b 15 00 08 11 37 07 11 37 93 28 15 00 00 0a 9c 00 11 37 17 58 13 37 11 37 08 8e 69 fe 04 13 38 11 38 2d de } //00 00 
	condition:
		any of ($a_*)
 
}