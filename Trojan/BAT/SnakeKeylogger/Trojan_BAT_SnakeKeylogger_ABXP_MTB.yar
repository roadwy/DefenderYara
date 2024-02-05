
rule Trojan_BAT_SnakeKeylogger_ABXP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 3d 16 0b 2b 25 11 06 06 07 6f 90 01 01 00 00 0a 13 1e 12 1e 28 90 01 01 00 00 0a 13 17 11 0c 11 07 11 17 9c 11 07 17 58 13 07 07 17 58 0b 07 11 06 6f 90 01 01 00 00 0a fe 04 13 18 11 18 2d cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}