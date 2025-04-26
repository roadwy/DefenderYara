
rule Trojan_BAT_SnakeLogger_BD_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 ?? 11 ?? 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b ?? 09 16 fe 02 13 ?? 11 ?? 2c 65 00 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 ?? 16 13 ?? 2b 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}