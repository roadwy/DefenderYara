
rule Trojan_BAT_SnakeKeylogger_ZNJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 13 09 12 08 28 ?? 00 00 0a 13 0a 12 08 28 ?? 00 00 0a 13 0b 09 11 09 11 05 11 06 58 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}