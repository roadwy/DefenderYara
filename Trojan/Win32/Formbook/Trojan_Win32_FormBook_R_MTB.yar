
rule Trojan_Win32_FormBook_R_MTB{
	meta:
		description = "Trojan:Win32/FormBook.R!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 f1 43 e2 db ec } //1
		$a_01_1 = {89 0c 18 39 } //1
		$a_01_2 = {81 f1 d8 79 24 d6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}