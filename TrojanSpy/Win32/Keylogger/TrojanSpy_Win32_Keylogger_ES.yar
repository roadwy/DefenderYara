
rule TrojanSpy_Win32_Keylogger_ES{
	meta:
		description = "TrojanSpy:Win32/Keylogger.ES,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 61 76 70 66 77 2e 65 78 65 } //01 00  Kavpfw.exe
		$a_01_1 = {45 67 68 6f 73 74 2e 65 78 65 } //01 00  Eghost.exe
		$a_01_2 = {52 61 76 6d 6f 6e 2e 65 78 65 } //01 00  Ravmon.exe
		$a_01_3 = {50 66 77 2e 65 78 65 } //01 00  Pfw.exe
		$a_01_4 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 } //01 00  Explorer.EXE
		$a_01_5 = {4e 65 74 62 61 72 67 70 2e 65 78 65 } //01 00  Netbargp.exe
		$a_01_6 = {4b 4d 61 69 6c 4d 6f 6e 2e 65 78 65 } //01 00  KMailMon.exe
		$a_01_7 = {49 70 61 72 6d 6f 72 2e 65 78 65 } //01 00  Iparmor.exe
		$a_01_8 = {4b 76 6d 6f 6e 78 70 2e 65 78 65 } //01 00  Kvmonxp.exe
		$a_01_9 = {5c 71 69 6a 69 61 6e 2e 65 78 65 } //01 00  \qijian.exe
		$a_01_10 = {5c 71 69 6a 69 61 6e 2e 64 6c 6c } //01 00  \qijian.dll
		$a_01_11 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}