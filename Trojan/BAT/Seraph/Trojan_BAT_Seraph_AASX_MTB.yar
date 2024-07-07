
rule Trojan_BAT_Seraph_AASX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 08 28 90 01 01 04 00 06 25 17 28 90 01 01 04 00 06 25 18 28 90 01 01 04 00 06 25 06 28 90 01 01 04 00 06 28 90 01 01 04 00 06 07 16 07 8e 69 28 90 01 01 04 00 06 0d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}