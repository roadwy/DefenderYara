
rule Trojan_Win64_BlackWidow_GVC_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 11 } //1
		$a_01_1 = {44 30 14 0f } //3 い༔
		$a_01_2 = {49 81 c1 12 ce 2b 00 } //1
		$a_02_3 = {48 81 f9 d3 ?? ?? ?? 0f 86 07 f6 ff ff } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_02_3  & 1)*2) >=7
 
}