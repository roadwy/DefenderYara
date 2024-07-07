
rule Trojan_Win32_Cendelf_gen_A{
	meta:
		description = "Trojan:Win32/Cendelf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 65 74 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c } //4
		$a_01_1 = {81 ff 91 68 84 25 75 } //1
		$a_01_2 = {81 fe 24 74 98 26 75 } //1
		$a_01_3 = {81 7d 08 24 74 98 26 75 } //1
		$a_01_4 = {81 7d 08 91 68 84 25 75 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}