
rule Trojan_BAT_SnakeKeyLogger_AMX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? ?? 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 6f ?? ?? 00 0a 04 fe 04 16 fe 01 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_SnakeKeyLogger_AMX_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b de 22 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}