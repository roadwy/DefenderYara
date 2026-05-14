
rule Trojan_BAT_SnakeKeylogger_RVD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 06 6f ?? 00 00 0a 03 fe 04 13 04 11 04 2c 0e 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 fe 04 13 05 11 05 2c 0e 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 fe 04 13 06 11 06 2c 0e 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}