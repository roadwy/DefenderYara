
rule Trojan_Win32_FormBook_BN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a 00 75 00 6a 00 4c 00 76 00 67 00 77 00 4d 00 53 00 63 00 4d 00 30 00 6e 00 69 00 56 00 79 00 37 00 6a 00 75 00 6c 00 75 00 35 00 49 00 66 00 6c 00 61 00 50 00 37 00 6c 00 7a 00 7a 00 6b 00 46 00 55 00 55 00 76 00 4f 00 48 00 37 00 32 00 34 00 39 00 } //1 zujLvgwMScM0niVy7julu5IflaP7lzzkFUUvOH7249
		$a_01_1 = {68 00 61 00 6e 00 31 00 38 00 30 00 } //1 han180
		$a_00_2 = {47 73 38 4c 48 73 7a 4a 48 73 } //1 Gs8LHszJHs
		$a_00_3 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}