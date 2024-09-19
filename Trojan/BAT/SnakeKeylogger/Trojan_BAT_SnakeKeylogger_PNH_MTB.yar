
rule Trojan_BAT_SnakeKeylogger_PNH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 11 05 11 06 6f ?? 00 00 0a 13 07 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 20 00 40 01 00 fe 04 13 08 11 08 2c 0e 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 20 00 40 01 00 fe 04 13 09 11 09 2c 0e 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d 8c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}