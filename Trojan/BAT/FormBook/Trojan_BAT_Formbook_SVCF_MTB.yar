
rule Trojan_BAT_Formbook_SVCF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SVCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 0b 07 02 6f ?? 00 00 0a 32 c7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}