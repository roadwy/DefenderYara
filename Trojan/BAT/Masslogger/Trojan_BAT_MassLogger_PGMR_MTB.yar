
rule Trojan_BAT_MassLogger_PGMR_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.PGMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? ?? 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 07 7b ?? 00 00 04 20 80 00 00 00 59 6c 07 7b ?? 00 00 04 20 80 00 00 00 59 6c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}