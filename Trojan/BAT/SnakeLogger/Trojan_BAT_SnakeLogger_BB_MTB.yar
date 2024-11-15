
rule Trojan_BAT_SnakeLogger_BB_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 2b 2d 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 15 03 6f ?? 00 00 0a 19 58 04 31 03 16 2b 01 17 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}