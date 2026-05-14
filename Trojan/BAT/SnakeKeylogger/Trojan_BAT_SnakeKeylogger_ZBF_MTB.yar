
rule Trojan_BAT_SnakeKeylogger_ZBF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 13 04 12 03 28 ?? 00 00 0a 13 05 12 03 28 ?? 00 00 0a 13 06 11 04 07 28 ?? 00 00 06 13 04 11 05 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}