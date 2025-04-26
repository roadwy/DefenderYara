
rule Trojan_BAT_LummaC_GPPG_MTB{
	meta:
		description = "Trojan:BAT/LummaC.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2b 11 07 59 13 14 38 05 fd ff ff 11 26 11 13 61 13 0e } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}