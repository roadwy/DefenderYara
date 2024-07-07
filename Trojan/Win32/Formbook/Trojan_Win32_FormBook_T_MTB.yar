
rule Trojan_Win32_FormBook_T_MTB{
	meta:
		description = "Trojan:Win32/FormBook.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 0f 6e c6 90 02 10 66 0f 6e c9 90 02 10 66 0f ef c8 90 02 10 66 0f 7e c9 90 02 10 39 c1 90 13 0f 77 90 02 10 46 90 02 10 ff 37 90 02 10 59 90 00 } //2
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}