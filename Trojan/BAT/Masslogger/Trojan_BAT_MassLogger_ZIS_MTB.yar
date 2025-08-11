
rule Trojan_BAT_MassLogger_ZIS_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 12 00 02 11 2c 11 30 6f ?? 00 00 0a 13 31 11 17 12 31 28 ?? 00 00 0a 58 13 17 11 18 12 31 28 ?? 00 00 0a 58 13 18 11 19 12 31 28 ?? 00 00 0a 58 13 19 12 31 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}