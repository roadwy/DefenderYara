
rule Trojan_BAT_MassLogger_ADAB_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ADAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 09 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6c 05 7b ?? 00 00 04 06 1f 10 5d 99 23 fc a9 f1 d2 4d 62 50 3f 5a 58 13 05 12 04 28 ?? 00 00 0a 6c 0e 04 7b ?? 00 00 04 09 1f 09 5d 99 23 fc a9 f1 d2 4d 62 50 3f 5a 58 13 06 12 04 28 ?? 00 00 0a 6c 0e 04 7b ?? 00 00 04 23 00 00 00 00 00 00 59 40 5a 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}