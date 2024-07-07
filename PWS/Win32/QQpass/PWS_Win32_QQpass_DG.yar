
rule PWS_Win32_QQpass_DG{
	meta:
		description = "PWS:Win32/QQpass.DG,SIGNATURE_TYPE_PEHSTR_EXT,12 00 11 00 12 00 00 "
		
	strings :
		$a_00_0 = {77 67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //1 wgameclient.exe
		$a_01_1 = {63 61 62 61 6c 6d 61 69 6e 2e 65 78 65 } //1 cabalmain.exe
		$a_00_2 = {71 71 67 61 6d 65 2e 65 78 65 } //1 qqgame.exe
		$a_00_3 = {57 4f 57 2e 45 58 45 } //1 WOW.EXE
		$a_00_4 = {00 71 71 2e 65 78 65 } //1
		$a_00_5 = {57 4f 57 2e 50 53 } //1 WOW.PS
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_8 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_9 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_00_10 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_11 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_12 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
		$a_01_13 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_14 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_15 = {73 74 72 72 63 68 72 } //1 strrchr
		$a_00_16 = {2e 5c 57 54 46 5c 63 6f 6e 66 69 67 2e 77 74 66 } //1 .\WTF\config.wtf
		$a_00_17 = {4c 61 54 61 6c 65 43 6c 69 65 6e 74 2e 45 58 45 } //1 LaTaleClient.EXE
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1) >=17
 
}