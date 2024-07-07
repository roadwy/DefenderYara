
rule Trojan_BAT_zgRAT_RDC_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 03 16 11 03 8e 69 6f 97 00 00 0a 13 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}