
rule Trojan_BAT_Seraph_CMAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.CMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 28 90 01 01 00 00 0a 38 90 01 01 00 00 00 07 16 3c 90 01 01 00 00 00 28 90 01 01 00 00 06 38 90 01 01 00 00 00 28 90 01 01 00 00 06 06 28 90 01 01 00 00 0a 0c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}