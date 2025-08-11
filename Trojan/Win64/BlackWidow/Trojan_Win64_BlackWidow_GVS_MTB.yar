
rule Trojan_Win64_BlackWidow_GVS_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 81 c0 c6 cf 0e 00 c5 f5 fd f9 } //2
		$a_01_1 = {45 8a 14 10 } //1
		$a_01_2 = {44 30 14 0f } //1 い༔
		$a_01_3 = {48 ff c1 0f 28 f0 } //1
		$a_01_4 = {48 89 c8 66 44 0f 38 de c1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}