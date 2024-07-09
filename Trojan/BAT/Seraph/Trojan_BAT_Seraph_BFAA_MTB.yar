
rule Trojan_BAT_Seraph_BFAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.BFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 75 01 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 2a 11 01 17 58 13 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}