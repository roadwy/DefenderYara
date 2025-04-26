
rule Trojan_BAT_LummaC_SPYF_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SPYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 38 11 36 16 6f ?? 00 00 0a 61 d2 13 38 38 24 00 00 00 } //2
		$a_01_1 = {11 2e 11 2f 04 11 2f 05 5d 91 9c 20 04 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}