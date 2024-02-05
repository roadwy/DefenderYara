
rule Trojan_BAT_SnakeLogger_FAY_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.FAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f 90 01 01 01 00 0a 0b 07 8e 69 17 da 17 d6 8d 90 01 01 00 00 01 0c 07 8e 69 17 da 13 06 16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 90 01 01 01 00 0a 9c 11 07 17 d6 13 07 11 07 11 06 31 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}