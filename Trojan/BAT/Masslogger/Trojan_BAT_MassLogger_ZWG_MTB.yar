
rule Trojan_BAT_MassLogger_ZWG_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 01 00 0a 13 06 12 06 28 ?? 01 00 0a 13 07 12 06 28 ?? 01 00 0a 13 08 12 06 28 ?? 01 00 0a 13 09 12 07 12 08 12 09 28 ?? 00 00 06 00 11 07 19 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}