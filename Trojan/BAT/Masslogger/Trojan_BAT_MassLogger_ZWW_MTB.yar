
rule Trojan_BAT_MassLogger_ZWW_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 16 13 07 38 ?? 00 00 00 11 07 11 05 11 06 11 07 11 04 11 07 59 6f ?? 00 00 0a 58 13 07 11 07 11 04 32 e5 03 72 ?? 00 00 70 11 06 6f ?? 00 00 06 17 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}