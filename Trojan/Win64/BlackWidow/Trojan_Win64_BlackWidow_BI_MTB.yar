
rule Trojan_Win64_BlackWidow_BI_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 8a 1c 11 } //1
		$a_01_1 = {44 30 1c 0f } //1 い༜
		$a_01_2 = {47 64 36 5e 70 48 62 4d 61 49 6d 38 34 64 4b 3f 43 4c 78 5e 46 } //3 Gd6^pHbMaIm84dK?CLx^F
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}