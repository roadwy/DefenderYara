
rule Trojan_BAT_LummaC_CXIJ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.CXIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 04 02 11 04 91 11 01 61 11 00 11 03 91 61 d2 9c 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}