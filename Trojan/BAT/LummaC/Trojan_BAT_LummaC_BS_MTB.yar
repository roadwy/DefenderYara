
rule Trojan_BAT_LummaC_BS_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 59 11 01 59 20 ff 00 00 00 5f d2 } //3
		$a_01_1 = {02 11 01 91 13 } //1
		$a_01_2 = {02 03 1f 1f 5f 63 02 1e 03 59 1f 1f 5f 62 60 d2 2a } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}