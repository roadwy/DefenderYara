
rule Trojan_BAT_Heracles_AGEA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AGEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 05 58 47 52 00 11 05 17 58 13 05 11 05 28 90 01 03 06 8e 69 fe 04 13 06 11 06 2d d4 00 14 13 04 07 28 90 01 03 06 8e 69 6a 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}