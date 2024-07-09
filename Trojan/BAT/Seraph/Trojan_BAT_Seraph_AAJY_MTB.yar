
rule Trojan_BAT_Seraph_AAJY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 03 38 ?? ff ff ff 11 02 11 06 11 00 94 58 13 02 38 ?? 00 00 00 11 06 11 00 94 13 04 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}