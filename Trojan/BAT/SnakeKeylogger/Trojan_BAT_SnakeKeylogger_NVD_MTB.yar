
rule Trojan_BAT_SnakeKeylogger_NVD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 7e 90 01 03 04 5d 91 0a 16 0b 02 03 28 90 01 03 06 0c 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e 90 01 03 04 5d 07 d2 9c 02 13 04 11 04 90 00 } //01 00 
		$a_03_1 = {04 5d 91 0a 06 7e 90 01 03 04 03 1f 16 5d 6f 90 01 03 0a 61 0b 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}