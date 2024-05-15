
rule Trojan_BAT_Rozena_JVAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.JVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 8e 69 8d 90 01 01 00 00 01 0c 16 13 05 2b 17 00 08 11 05 07 11 05 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}