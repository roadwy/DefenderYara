
rule TrojanSpy_Win32_Logsnif_gen_F{
	meta:
		description = "TrojanSpy:Win32/Logsnif.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 08 00 00 "
		
	strings :
		$a_03_0 = {7a 7a 61 72 64 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 5c 57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 [0-20] 49 6e 73 74 61 6c 6c 50 61 74 68 00 } //1
		$a_01_1 = {00 47 78 57 69 6e 64 6f 77 43 00 } //1
		$a_01_2 = {00 00 3d 0d 1c 00 00 7f 2c 0f 84 } //3
		$a_01_3 = {75 2f 83 7e 04 4b 75 19 6a 00 } //3
		$a_01_4 = {50 c1 ee 10 81 e6 ff 00 00 00 56 53 } //3
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_01_6 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //10 GetKeyboardState
		$a_01_7 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //10 GetForegroundWindow
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=37
 
}