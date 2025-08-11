
rule Trojan_BAT_MassLogger_PGM_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 31 11 34 6f ?? 00 00 0a 13 37 12 37 28 ?? 00 00 0a 06 61 d2 13 38 12 37 28 ?? 00 00 0a 06 61 d2 13 39 12 37 28 ?? 00 00 0a 06 61 d2 13 3a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}