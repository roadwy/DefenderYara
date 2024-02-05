
rule Trojan_BAT_Bladabindi_MBFP_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 2c 4c 07 06 28 90 01 01 00 00 0a 72 63 01 00 70 03 18 8c 90 01 01 00 00 01 06 28 90 01 01 00 00 0a 17 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 18 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a b4 9c 00 06 11 05 12 00 28 90 01 01 00 00 0a 13 06 11 06 2d b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}