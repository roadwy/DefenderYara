
rule Trojan_Win64_BlackWidow_GVG_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 11 } //1
		$a_01_1 = {44 30 14 0f } //3 い༔
		$a_01_2 = {48 81 f9 d3 35 01 00 0f 86 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=5
 
}