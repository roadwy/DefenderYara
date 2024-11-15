
rule Trojan_BAT_LummaC_RDC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 02 08 91 07 08 07 6f 21 00 00 0a 5d 6f 22 00 00 0a 61 d2 9c 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}