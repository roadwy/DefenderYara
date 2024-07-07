
rule Trojan_Win32_FormBook_CB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 57 56 83 ec 0c 31 c0 89 44 24 04 6a 40 68 00 30 00 00 68 00 84 d7 17 } //5
		$a_01_1 = {b9 00 7c 28 e8 c6 84 08 00 84 d7 17 00 41 75 f5 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}