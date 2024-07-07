
rule Trojan_Win32_FormBook_AD_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 90 02 10 66 0f 74 c1 90 02 10 66 0f 6e e6 90 02 10 66 0f 6e e9 90 02 10 66 0f 57 ec 90 02 10 66 0f 7e e9 90 02 10 39 c1 74 90 00 } //1
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FormBook_AD_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {38 1c 01 74 0e 40 3d 00 01 00 00 7c f3 8b 85 f4 fe fe ff 8a 84 05 fc fe ff ff 88 06 8b 85 f8 fe fe ff 46 4f } //10
		$a_02_1 = {55 8b ec 83 ec 20 a1 90 01 04 33 c5 89 45 fc a1 90 01 04 53 56 57 a8 01 75 17 83 c8 01 6a 0c 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}