
rule Trojan_BAT_SnakeKeylogger_AAT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 6f ?? 00 00 0a 16 03 6f ?? 00 00 0a 0a 12 00 1f 23 1f 6e 28 ?? 00 00 06 73 ?? 00 00 0a a2 25 17 03 6f ?? 00 00 0a 17 03 6f ?? 00 00 0a 0a 12 00 20 ?? 02 00 00 20 ?? 02 00 00 28 ?? 00 00 06 73 ?? 00 00 0a a2 25 18 03 6f ?? 00 00 0a 18 03 6f ?? 00 00 0a 0a 12 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}