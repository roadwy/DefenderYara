
rule Trojan_BAT_SnakeKeylogger_RVE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 11 04 11 05 6f ?? 00 00 0a 13 06 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 13 07 11 07 2c 13 06 7b ?? 00 00 04 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 13 08 11 08 2c 13 06 7b ?? 00 00 04 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 13 09 11 09 2c 13 06 7b ?? 00 00 04 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}