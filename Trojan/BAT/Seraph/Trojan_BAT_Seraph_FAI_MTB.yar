
rule Trojan_BAT_Seraph_FAI_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 2a 11 04 18 5b 8d ?? 00 00 01 13 02 20 04 00 00 00 38 ?? ff ff ff 11 03 18 58 13 03 38 ?? ff ff ff 11 02 11 03 18 5b 11 00 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 0a 9c 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}