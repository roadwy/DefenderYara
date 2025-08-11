
rule Trojan_BAT_SnakeLogger_AWXA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AWXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 21 17 11 26 16 94 11 26 17 94 58 1f 0a 5d 58 13 22 11 26 16 94 13 48 11 26 17 94 13 49 02 11 48 11 49 6f ?? 00 00 0a 13 4a 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5a 11 5a 2c 08 72 ?? 08 00 70 0c 2b 3e 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5b 11 5b 2c 08 72 ?? 08 00 70 0c 2b 22 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5c 11 5c 2c 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}