
rule Trojan_BAT_SnakeLogger_ACF_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 26 12 24 28 ?? 00 00 0a 13 27 11 25 11 26 58 11 27 58 13 28 11 28 1f 1f 61 13 28 04 03 6f ?? 00 00 0a 59 13 29 11 29 17 } //4
		$a_03_1 = {2b 24 03 11 25 6f ?? 00 00 0a 00 03 11 26 6f ?? 00 00 0a 00 2b 10 03 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}