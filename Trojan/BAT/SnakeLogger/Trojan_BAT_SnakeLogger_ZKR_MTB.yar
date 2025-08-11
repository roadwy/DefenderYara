
rule Trojan_BAT_SnakeLogger_ZKR_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ZKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 1d 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 0e 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}