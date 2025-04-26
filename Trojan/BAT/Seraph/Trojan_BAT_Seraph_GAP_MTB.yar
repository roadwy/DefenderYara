
rule Trojan_BAT_Seraph_GAP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d df 2b f3 2b dd 00 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 16 2c 08 26 2b 00 16 2d d4 de c2 0a 2b f6 26 2b 00 de ba } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}