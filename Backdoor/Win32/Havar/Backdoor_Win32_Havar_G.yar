
rule Backdoor_Win32_Havar_G{
	meta:
		description = "Backdoor:Win32/Havar.G,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 65 6c 66 44 65 6c 65 74 65 2e 62 61 74 } //1 SelfDelete.bat
		$a_00_1 = {69 66 20 45 58 49 53 54 20 } //1 if EXIST 
		$a_00_2 = {77 4b 42 50 53 45 56 41 78 67 48 45 57 57 41 57 78 4c 50 50 54 78 57 4c 41 48 48 78 4b 54 41 4a 78 47 4b 49 49 45 4a 40 } //1 wKBPSEVAxgHEWWAWxLPPTxWLAHHxKTAJxGKIIEJ@
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_00_4 = {57 69 6e 33 32 20 53 65 72 76 69 63 65 } //1 Win32 Service
		$a_00_5 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_02_6 = {89 03 b8 8f 23 68 da e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 ad b6 4d 81 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 a8 ed f2 ce e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 f8 19 42 5b e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 cc 97 10 25 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 1c 1c 60 30 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 78 5c 3b 55 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 74 ea c7 ef e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 d0 03 5c 09 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 65 41 fb a7 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 f4 15 93 b0 e8 ?? ?? 00 00 a3 ?? ?? 40 00 b8 cb 6b 9b 91 } //1
		$a_00_7 = {ba a1 25 00 00 b9 50 78 01 00 b8 96 ff 92 00 03 c0 03 d1 03 d0 8b ca 2b c8 03 c8 03 c8 2b c8 8b c1 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}