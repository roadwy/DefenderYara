
rule Trojan_Win32_DelfInject_AM_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {50 72 69 6e 74 20 53 63 72 65 65 6e 20 74 6f 20 46 69 6c 65 } //3 Print Screen to File
		$a_81_1 = {53 63 72 65 65 6e 2e 62 6d 70 } //3 Screen.bmp
		$a_81_2 = {54 00 45 00 43 00 4f 00 05 00 54 00 45 00 43 00 4f 00 4d } //3
		$a_81_3 = {50 69 63 74 75 72 65 2e 44 61 74 61 } //3 Picture.Data
		$a_81_4 = {77 69 6e 68 74 74 70 } //3 winhttp
		$a_81_5 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //3 DllGetClassObject
		$a_81_6 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //3 ActivateKeyboardLayout
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}