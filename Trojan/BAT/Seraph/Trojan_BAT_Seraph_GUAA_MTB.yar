
rule Trojan_BAT_Seraph_GUAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 03 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 03 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}