
rule TrojanDownloader_Win32_Fiansrch_B{
	meta:
		description = "TrojanDownloader:Win32/Fiansrch.B,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_01_1 = {46 69 61 6e 53 65 61 72 63 68 2e 65 78 65 } //01 00  FianSearch.exe
		$a_01_2 = {66 69 61 6e 66 78 6d 73 67 73 2e 64 6c 6c } //01 00  fianfxmsgs.dll
		$a_01_3 = {66 7a 6d 73 67 73 75 70 64 61 74 65 2e 65 78 65 } //01 00  fzmsgsupdate.exe
		$a_01_4 = {66 73 65 61 72 63 68 2e 66 69 61 6e 2e 63 6f 2e 6b 72 } //01 00  fsearch.fian.co.kr
		$a_01_5 = {45 41 42 37 41 41 30 31 2d 43 41 41 41 2d 34 43 33 34 2d 38 33 34 33 2d 35 35 37 43 37 45 36 33 42 37 33 42 } //01 00  EAB7AA01-CAAA-4C34-8343-557C7E63B73B
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_9 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_10 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  UnhookWindowsHookEx
	condition:
		any of ($a_*)
 
}