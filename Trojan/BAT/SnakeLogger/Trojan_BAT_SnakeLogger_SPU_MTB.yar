
rule Trojan_BAT_SnakeLogger_SPU_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 71 00 06 19 11 04 5a 6f 90 01 03 0a 13 05 11 05 1f 39 fe 02 13 07 11 07 2c 0d 11 05 1f 41 59 1f 0a 58 d1 13 05 2b 08 11 05 1f 30 59 d1 13 05 06 19 11 04 5a 17 58 6f 90 01 03 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}