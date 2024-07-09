
rule PWS_Win32_Frethog_gen_J{
	meta:
		description = "PWS:Win32/Frethog.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,13 00 11 00 0d 00 00 "
		
	strings :
		$a_00_0 = {60 e8 00 00 00 00 58 b9 } //3
		$a_02_1 = {72 6f 6c 65 3d 00 [0-10] 70 69 6e 3d } //3
		$a_00_2 = {58 61 81 c7 a0 00 00 00 } //2
		$a_02_3 = {67 61 6d 65 69 64 3d 00 [0-04] 26 } //2
		$a_00_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //2 Accept-Language: zh-cn
		$a_00_5 = {50 61 73 73 77 6f 72 64 44 6c 67 } //2 PasswordDlg
		$a_00_6 = {74 72 6f 6a 61 6e 6b 69 6c 6c 65 72 } //1 trojankiller
		$a_00_7 = {48 74 74 70 51 } //1 HttpQ
		$a_00_8 = {7a 68 65 6e 67 74 75 } //1 zhengtu
		$a_00_9 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e } //1 CurrentControlSet\Control\Session
		$a_01_10 = {48 6f 6f 6b } //1 Hook
		$a_01_11 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_12 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
	condition:
		((#a_00_0  & 1)*3+(#a_02_1  & 1)*3+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_00_12  & 1)*1) >=17
 
}