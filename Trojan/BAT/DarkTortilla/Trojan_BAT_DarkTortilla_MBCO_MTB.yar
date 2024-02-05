
rule Trojan_BAT_DarkTortilla_MBCO_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 2c 5f 07 07 72 67 0a 00 70 6f 90 01 01 00 00 0a 17 d6 73 90 01 01 00 00 0a 17 1f 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0d 09 72 6b 0a 00 70 6f 90 01 01 00 00 0a 13 04 11 04 2c 2b 28 90 01 01 00 00 06 13 05 11 05 16 fe 01 13 06 11 06 2c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}