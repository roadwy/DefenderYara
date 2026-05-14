
rule Trojan_BAT_MassLogger_ZAF_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 11 11 12 6f ?? 00 00 0a 13 13 11 0b 03 fe 04 13 14 11 14 39 17 00 00 00 00 11 08 12 13 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 58 13 0b 00 11 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}