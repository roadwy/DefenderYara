
rule Trojan_Win64_BlackWidow_BY_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 30 14 0f } //2 い༔
		$a_01_1 = {c4 e3 fd 00 ff d8 45 8a 14 10 } //1
		$a_01_2 = {c5 cd 71 d6 08 c5 cd db f7 } //1
		$a_01_3 = {c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}