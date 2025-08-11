
rule Trojan_BAT_SnakeLogger_AEXA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AEXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 07 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 13 04 2b 1f 2b 21 16 2b 21 8e 69 2b 20 2b 25 2b 27 72 ?? ?? 00 70 2b 23 16 2c 24 26 26 26 17 2b 25 de 5d 11 04 2b dd 06 2b dc 06 2b dc 6f ?? 00 00 0a 2b d9 13 05 2b d7 03 2b d6 11 05 2b d9 28 ?? 00 00 06 2b d8 13 06 2b d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}