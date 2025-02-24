
rule Trojan_BAT_LummaC_AAC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 37 02 11 33 91 13 37 11 37 11 36 16 6f ?? 00 00 0a 61 d2 13 37 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}