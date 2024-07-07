
rule Trojan_BAT_zgRAT_KAC_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 50 11 02 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 1f 58 61 d2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}