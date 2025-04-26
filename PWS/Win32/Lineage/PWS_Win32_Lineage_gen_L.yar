
rule PWS_Win32_Lineage_gen_L{
	meta:
		description = "PWS:Win32/Lineage.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0a 00 00 "
		
	strings :
		$a_00_0 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //5 Accept-Language: zh-cn
		$a_01_1 = {c6 44 24 18 26 c6 44 24 19 6d c6 44 24 1a 6f c6 44 24 1b 64 } //5
		$a_01_2 = {69 6e 65 61 67 65 2e 65 78 65 } //1 ineage.exe
		$a_01_3 = {4c 69 6e 65 61 67 65 20 57 69 6e 64 6f 77 73 20 43 6c 69 65 6e 74 } //1 Lineage Windows Client
		$a_01_4 = {3f 6d 61 69 6c 62 6f 64 79 3d } //1 ?mailbody=
		$a_01_5 = {53 65 6e 64 6d 61 69 6c 2e 65 78 65 } //1 Sendmail.exe
		$a_01_6 = {4d 75 6d 61 00 } //1
		$a_01_7 = {2e 64 61 74 00 61 73 64 66 } //1
		$a_00_8 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //10 GetWindowTextA
		$a_01_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*10+(#a_01_9  & 1)*10) >=29
 
}