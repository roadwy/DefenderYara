
rule Trojan_BAT_SnakeKeyLogger_AMX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? ?? 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 6f ?? ?? 00 0a 04 fe 04 16 fe 01 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}