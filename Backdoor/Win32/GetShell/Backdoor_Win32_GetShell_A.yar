
rule Backdoor_Win32_GetShell_A{
	meta:
		description = "Backdoor:Win32/GetShell.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //1
		$a_03_1 = {68 58 a4 53 e5 90 05 01 02 90 90 90 18 90 05 01 02 90 90 ff d5 90 00 } //1
		$a_01_2 = {97 6a 05 68 ba 57 45 f9 68 02 00 1f 92 89 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}