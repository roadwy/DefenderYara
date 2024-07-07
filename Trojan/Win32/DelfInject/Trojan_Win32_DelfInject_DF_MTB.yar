
rule Trojan_Win32_DelfInject_DF_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 65 6e 64 4d 61 69 6c } //3 SendMail
		$a_81_1 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //3 LockResource
		$a_81_2 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //3 WinHttpCrackUrl
		$a_81_3 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //3 ActivateKeyboardLayout
		$a_81_4 = {41 75 74 6f 48 6f 74 6b 65 79 73 54 } //3 AutoHotkeysT
		$a_01_5 = {5a 00 41 00 4d 00 4f 00 52 00 05 00 43 00 48 00 45 00 43 00 4d } //3
		$a_01_6 = {42 00 42 00 41 00 42 00 4f 00 52 00 54 00 05 00 42 00 42 00 41 00 4c 00 4c } //3
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=21
 
}