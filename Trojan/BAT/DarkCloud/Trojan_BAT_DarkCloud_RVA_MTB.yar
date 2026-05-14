
rule Trojan_BAT_DarkCloud_RVA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 13 04 12 03 28 ?? 00 00 0a 13 05 12 03 28 ?? 00 00 0a 13 06 11 04 07 08 58 28 ?? 00 00 06 13 04 11 05 07 18 5a 28 ?? 00 00 06 13 05 11 06 08 18 5a 28 ?? 00 00 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}