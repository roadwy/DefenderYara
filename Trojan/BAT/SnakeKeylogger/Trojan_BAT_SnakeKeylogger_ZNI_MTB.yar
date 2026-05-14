
rule Trojan_BAT_SnakeKeylogger_ZNI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 13 08 12 07 28 ?? 00 00 0a 13 09 12 07 28 ?? 00 00 0a 13 0a 11 08 11 05 28 ?? 00 00 06 13 08 11 09 11 05 17 58 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}