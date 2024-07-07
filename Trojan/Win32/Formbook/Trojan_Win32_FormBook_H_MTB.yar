
rule Trojan_Win32_FormBook_H_MTB{
	meta:
		description = "Trojan:Win32/FormBook.H!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 34 0f d9 d0 } //3
		$a_01_1 = {31 34 24 d9 d0 } //3
		$a_01_2 = {8f 04 08 39 db } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}