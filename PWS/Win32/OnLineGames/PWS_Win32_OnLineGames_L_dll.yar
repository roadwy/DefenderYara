
rule PWS_Win32_OnLineGames_L_dll{
	meta:
		description = "PWS:Win32/OnLineGames.L!dll,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_02_0 = {8b f3 85 f6 7e 1e bf 01 00 00 00 8b 5d 90 01 01 8b 45 90 01 01 e8 90 01 04 8a 13 80 f2 90 01 01 88 54 38 ff 47 43 4e 75 ea 8b 7d 90 01 01 8b 75 90 01 01 8b 5d 90 01 01 8b e5 5d c3 90 00 } //10
		$a_00_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_3 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_02_4 = {31 2e 68 69 76 90 09 04 00 43 3a 5c 90 00 } //1
		$a_00_5 = {00 48 6f 6f 6b 2e 64 6c 6c } //1
		$a_00_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=25
 
}