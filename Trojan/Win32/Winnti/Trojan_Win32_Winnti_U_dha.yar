
rule Trojan_Win32_Winnti_U_dha{
	meta:
		description = "Trojan:Win32/Winnti.U!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 6b 20 6e 65 74 73 76 63 73 00 } //1
		$a_01_1 = {61 76 70 2e 65 78 65 00 } //1
		$a_01_2 = {77 6f 72 6b 64 6c 6c 36 34 2e 64 6c 6c } //1 workdll64.dll
		$a_01_3 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b 13 72 e1 } //1
		$a_01_4 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}