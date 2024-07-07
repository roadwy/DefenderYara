
rule Trojan_Win32_VB_AER{
	meta:
		description = "Trojan:Win32/VB.AER,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 47 65 74 49 45 4f 62 6a 65 63 74 } //3 ModGetIEObject
		$a_01_1 = {4d 6f 64 47 65 74 50 72 6f 63 65 73 73 4e 61 6d 65 42 79 50 72 6f 63 65 73 73 49 64 } //3 ModGetProcessNameByProcessId
		$a_01_2 = {53 00 48 00 45 00 4c 00 4c 00 48 00 4f 00 4f 00 4b 00 } //2 SHELLHOOK
		$a_01_3 = {4d 00 61 00 78 00 74 00 68 00 6f 00 6e 00 32 00 5f 00 56 00 69 00 65 00 77 00 } //2 Maxthon2_View
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=10
 
}