
rule Trojan_BAT_SnakeLogger_PGSL_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.PGSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 fd 09 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 0b 07 72 0d 0a 00 70 72 77 04 00 70 6f ?? 00 00 0a 72 13 0a 00 70 72 17 0a 00 70 6f ?? 00 00 0a 0b 07 17 8d ?? 00 00 01 25 16 1f 2d 9d 6f ?? 00 00 0a 0c 08 8e 69 8d ?? 00 00 01 0d 16 13 07 2b 17 00 09 11 07 08 11 07 9a 1f 10 28 ?? 00 00 0a 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}