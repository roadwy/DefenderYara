
rule Trojan_BAT_MassLogger_ZKF_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 12 09 28 ?? 00 00 0a 13 0b 12 09 28 ?? 00 00 0a 13 0c 12 09 28 ?? 00 00 0a 13 0d 11 0b 11 0c 58 11 0d 58 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}