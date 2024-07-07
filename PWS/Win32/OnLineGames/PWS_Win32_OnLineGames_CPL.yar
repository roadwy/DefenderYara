
rule PWS_Win32_OnLineGames_CPL{
	meta:
		description = "PWS:Win32/OnLineGames.CPL,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0e 00 00 "
		
	strings :
		$a_00_0 = {00 61 76 70 2e 65 78 65 } //10 愀灶攮數
		$a_00_1 = {4a 75 6d 70 4f 6e } //1 JumpOn
		$a_00_2 = {54 68 72 65 61 64 50 72 6f } //1 ThreadPro
		$a_00_3 = {67 61 6d 65 2e 65 78 65 } //1 game.exe
		$a_00_4 = {48 75 61 69 5f 48 75 61 69 } //10 Huai_Huai
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_6 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_00_7 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //1 OpenProcessToken
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_9 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_00_10 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_11 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_13 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //1 HttpOpenRequestA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_00_13  & 1)*1) >=31
 
}