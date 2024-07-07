
rule Trojan_BAT_Seraph_HNAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.HNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 04 11 00 11 04 91 11 02 11 04 11 02 28 90 01 01 00 00 06 5d 28 90 01 01 00 00 06 61 d2 9c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}