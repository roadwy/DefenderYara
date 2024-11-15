
rule Trojan_BAT_SnakeKeyLogger_KAD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 05 16 61 d2 6f ?? 00 00 0a 00 03 11 06 16 61 d2 6f ?? 00 00 0a 00 03 11 07 16 61 d2 6f ?? 00 00 0a 00 2b 15 03 6f ?? 00 00 0a 19 58 04 31 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}