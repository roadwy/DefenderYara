
rule Trojan_BAT_SnakeKeylogger_AABU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 b3 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 36 11 05 11 08 9a 72 b7 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 1a 11 05 11 08 9a 72 bb 02 00 70 28 ?? 00 00 0a 2c 09 12 0b 28 ?? 00 00 0a 13 0c 07 11 0c 6f ?? 00 00 0a 11 0a 17 58 13 0a 11 0a 09 32 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}