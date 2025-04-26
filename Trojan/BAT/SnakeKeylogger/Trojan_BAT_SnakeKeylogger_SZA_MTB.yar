
rule Trojan_BAT_SnakeKeylogger_SZA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 08 7e 08 00 00 04 11 08 91 28 46 00 00 0a 28 1f 00 00 06 6f 47 00 00 0a 11 08 28 46 00 00 0a 28 1f 00 00 06 6f 47 00 00 0a 8e 69 5d 91 61 d2 9c 00 11 08 17 58 13 08 11 08 7e 08 00 00 04 8e 69 fe 04 13 09 11 09 2d b5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}