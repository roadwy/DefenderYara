
rule Trojan_BAT_LummaC_RDA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 60 03 66 04 66 60 5f 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}