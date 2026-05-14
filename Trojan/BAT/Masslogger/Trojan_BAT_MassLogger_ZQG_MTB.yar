
rule Trojan_BAT_MassLogger_ZQG_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 11 02 11 10 11 11 6f ?? 00 00 0a 13 12 07 11 12 6f ?? 00 00 06 13 12 08 17 6f ?? 00 00 06 12 12 28 ?? 00 00 0a 13 0b 11 0b 28 ?? 00 00 06 28 ?? 00 00 06 13 0b 11 0b 18 62 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}