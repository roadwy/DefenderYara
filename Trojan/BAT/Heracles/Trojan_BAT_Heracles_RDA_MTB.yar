
rule Trojan_BAT_Heracles_RDA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 39 38 39 61 30 30 30 2d 33 63 30 63 2d 34 30 39 64 2d 38 34 34 38 2d 63 34 64 62 33 66 30 36 31 61 39 35 } //1 9989a000-3c0c-409d-8448-c4db3f061a95
		$a_01_1 = {74 65 73 74 34 30 34 } //1 test404
		$a_01_2 = {52 65 73 6f 75 72 63 65 73 } //1 Resources
		$a_01_3 = {41 62 6f 75 74 42 6f 78 31 } //1 AboutBox1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}