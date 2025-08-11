
rule Trojan_BAT_SnakeKeylogger_ZHU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 fe 04 16 fe 01 13 10 11 10 2c 2e 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 50 00 00 0a 6f ?? 00 00 0a 00 00 2b 58 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}