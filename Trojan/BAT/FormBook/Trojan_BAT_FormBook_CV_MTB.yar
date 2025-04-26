
rule Trojan_BAT_FormBook_CV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 16 11 02 11 00 1a 28 } //2
		$a_01_1 = {11 04 17 58 13 04 } //2 Б堗Г
		$a_03_2 = {11 07 5a 1a 5a 8d ?? 00 00 01 13 02 } //2
		$a_01_3 = {11 02 1a 11 03 16 11 03 8e 69 28 } //4
		$a_03_4 = {11 02 16 28 ?? 00 00 06 8d ?? 00 00 01 13 03 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*4+(#a_03_4  & 1)*2) >=12
 
}