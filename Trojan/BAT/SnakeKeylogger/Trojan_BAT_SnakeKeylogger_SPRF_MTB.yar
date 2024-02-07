
rule Trojan_BAT_SnakeKeylogger_SPRF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {00 06 03 07 8f 31 00 00 01 72 1d 01 00 70 28 90 01 03 0a 28 90 01 03 0a 0a 07 1c fe 04 0c 08 2c 0e 00 06 72 51 11 00 70 28 90 01 03 0a 0a 00 00 07 17 58 0b 07 1c fe 04 0d 09 2d c4 90 00 } //01 00 
		$a_01_1 = {49 45 45 45 5f 38 30 32 35 5f 54 6f 6b 65 6e 52 69 6e 67 } //00 00  IEEE_8025_TokenRing
	condition:
		any of ($a_*)
 
}