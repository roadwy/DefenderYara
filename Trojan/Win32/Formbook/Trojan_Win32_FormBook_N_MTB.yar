
rule Trojan_Win32_FormBook_N_MTB{
	meta:
		description = "Trojan:Win32/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 19 81 ff ?? ?? ?? ?? 81 fa } //2
		$a_02_1 = {31 1c 10 81 ff ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 83 c2 04 } //2
		$a_00_2 = {89 04 1f 71 } //1
		$a_00_3 = {35 a8 d6 00 6a eb } //3
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*3) >=4
 
}