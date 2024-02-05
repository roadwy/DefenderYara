
rule Trojan_BAT_SnakeKeylogger_ABSM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 19 11 14 5a 6f 90 01 01 00 00 0a 13 15 11 15 1f 39 fe 02 13 17 11 17 2c 0d 11 15 1f 41 59 1f 0a 58 d1 13 15 2b 08 11 15 1f 30 59 d1 13 15 06 19 11 14 5a 17 58 6f 90 01 01 00 00 0a 13 16 11 16 1f 39 fe 02 13 18 11 18 2c 0d 11 16 1f 41 59 1f 0a 58 d1 13 16 2b 08 11 16 1f 30 59 d1 13 16 08 11 14 1f 10 11 15 5a 11 16 58 d2 9c 00 11 14 17 58 13 14 11 14 07 fe 04 13 19 11 19 2d 84 90 00 } //01 00 
		$a_01_1 = {42 00 6f 00 61 00 72 00 64 00 47 00 61 00 6d 00 65 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}