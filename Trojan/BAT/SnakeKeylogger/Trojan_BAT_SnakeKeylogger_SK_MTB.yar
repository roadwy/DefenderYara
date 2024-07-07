
rule Trojan_BAT_SnakeKeylogger_SK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 09 58 17 58 17 59 11 08 11 0a 58 17 58 17 59 6f 90 01 03 0a 13 0b 12 0b 28 90 01 03 0a 13 0c 09 08 11 0c 9c 08 17 58 0c 11 0a 17 58 13 0a 00 11 0a 17 fe 04 13 0d 11 0d 2d c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}