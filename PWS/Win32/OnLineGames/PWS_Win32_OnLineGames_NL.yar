
rule PWS_Win32_OnLineGames_NL{
	meta:
		description = "PWS:Win32/OnLineGames.NL,SIGNATURE_TYPE_PEHSTR,0f 00 0e 00 0f 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 74 68 67 6f 6e 65 72 } //1 Forthgoner
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_2 = {48 42 51 51 2e 64 6c 6c } //1 HBQQ.dll
		$a_01_3 = {48 42 49 6e 6a 65 63 74 33 32 } //1 HBInject32
		$a_01_4 = {72 65 6e 61 6d 65 20 25 73 20 25 73 } //1 rename %s %s
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
		$a_01_7 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //1 AppInit_DLLs
		$a_01_8 = {50 72 6f 67 72 61 6d 20 4d 61 6e 61 67 65 72 } //1 Program Manager
		$a_01_9 = {57 4d 5f 48 4f 4f 4b 45 58 5f 52 4b } //1 WM_HOOKEX_RK
		$a_01_10 = {42 61 73 69 63 43 74 72 6c 44 6c 6c 2e 64 6c 6c } //1 BasicCtrlDll.dll
		$a_01_11 = {64 31 30 3d 25 73 26 64 31 31 3d 25 73 } //1 d10=%s&d11=%s
		$a_01_12 = {46 59 5f 50 41 53 53 57 4f 52 44 } //1 FY_PASSWORD
		$a_01_13 = {68 74 74 70 3a 2f 2f 77 6f 79 61 6f 73 68 65 2e 63 6f 6d 2f 69 70 74 65 73 74 2f 74 2f 78 63 6c 79 2e 61 73 70 } //1 http://woyaoshe.com/iptest/t/xcly.asp
		$a_01_14 = {4f 53 54 55 52 4c } //1 OSTURL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=14
 
}