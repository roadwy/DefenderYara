
rule Trojan_BAT_Seraph_BTAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.BTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1c de 20 28 ?? 00 00 06 2b e5 0a 2b e4 06 2b e6 06 2b e6 28 ?? 00 00 0a 2b e3 06 2b e2 0b 2b e1 26 de c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}