
rule Trojan_BAT_Seraph_GYAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 11 03 28 ?? 00 00 0a 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}