
rule Trojan_BAT_SnakeLogger_SPEA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 0a 11 05 11 0a 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 0a 17 58 13 0a 11 0a 11 05 8e 69 fe 04 13 0b 11 0b 2d d9 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}