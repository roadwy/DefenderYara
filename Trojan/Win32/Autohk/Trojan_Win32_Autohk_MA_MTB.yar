
rule Trojan_Win32_Autohk_MA_MTB{
	meta:
		description = "Trojan:Win32/Autohk.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {33 c9 66 89 0d b8 6c 4c 00 be 2c b0 4a 00 bb 01 00 00 00 89 35 c0 6e 4c 00 c6 44 24 34 00 c6 44 24 2e 00 89 5c 24 30 39 1d c4 41 4c 00 0f 8e ?? ?? ?? ?? 80 7c 24 2e 00 a1 cc 41 4c 00 8b 3c 98 0f 84 ?? ?? ?? ?? 8b 4c 24 30 51 8d 54 24 44 68 a8 08 4a 00 52 e8 } //1
		$a_01_1 = {6f 78 62 76 57 71 62 53 74 } //1 oxbvWqbSt
		$a_01_2 = {41 75 74 6f 48 6f 74 6b 65 79 } //1 AutoHotkey
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_5 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_01_6 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 57 } //1 SetWindowsHookExW
		$a_01_7 = {4e 00 75 00 6d 00 70 00 61 00 64 00 50 00 67 00 44 00 6e 00 } //1 NumpadPgDn
		$a_01_8 = {44 00 65 00 74 00 65 00 63 00 74 00 48 00 69 00 64 00 64 00 65 00 6e 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //1 DetectHiddenWindows
		$a_01_9 = {55 00 52 00 4c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 54 00 6f 00 46 00 69 00 6c 00 65 00 } //1 URLDownloadToFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}