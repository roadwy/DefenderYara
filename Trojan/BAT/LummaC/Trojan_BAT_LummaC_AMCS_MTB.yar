
rule Trojan_BAT_LummaC_AMCS_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 01 11 01 16 11 01 8e 69 6f ?? 00 00 0a 13 05 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}