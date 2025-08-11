
rule Trojan_BAT_SnakeLogger_ZOQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ZOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 0d 11 1d 6f ?? 00 00 0a 13 1e 72 ?? 0a 00 70 12 1e 28 ?? 00 00 0a 8c ?? 00 00 01 12 1e 28 ?? 00 00 0a 8c ?? 00 00 01 12 1e 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 13 1f 11 1f 6f ?? 00 00 0a 1c fe 01 13 20 } //6
		$a_03_1 = {13 3a 11 3a 2c 26 00 0e 07 11 1d 91 12 1e 28 ?? 00 00 0a 61 d2 13 3b 11 3b 1f 7f 30 07 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}