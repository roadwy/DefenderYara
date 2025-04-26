
rule Trojan_BAT_MassLogger_ARPA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ARPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 07 04 03 6f ?? 00 00 0a 59 13 08 07 72 a9 00 00 70 28 ?? 00 00 0a 2c 11 11 08 1f 64 31 0b 11 08 1f 64 28 ?? 00 00 0a 13 08 11 08 19 32 60 } //3
		$a_03_1 = {01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}