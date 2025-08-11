
rule Trojan_Win32_FormBook_ZC_MTB{
	meta:
		description = "Trojan:Win32/FormBook.ZC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 34 1c 7b e1 } //1
		$a_01_1 = {68 38 2a 90 c5 } //1
		$a_01_2 = {68 53 d8 7f 8c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}