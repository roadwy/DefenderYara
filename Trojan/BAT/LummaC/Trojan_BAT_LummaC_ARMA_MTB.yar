
rule Trojan_BAT_LummaC_ARMA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ARMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 69 11 68 16 6f ?? 00 00 0a 61 d2 13 69 38 } //3
		$a_01_1 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}