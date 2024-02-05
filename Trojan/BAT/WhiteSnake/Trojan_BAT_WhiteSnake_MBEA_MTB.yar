
rule Trojan_BAT_WhiteSnake_MBEA_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.MBEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 7e 46 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 00 28 90 01 01 00 00 06 00 00 00 11 05 16 fe 01 13 07 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}