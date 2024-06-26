
rule TrojanDownloader_Win32_Funnet_A{
	meta:
		description = "TrojanDownloader:Win32/Funnet.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 61 6c 65 72 2e 64 6c 6c } //01 00  Dialer.dll
		$a_01_1 = {49 6e 65 74 4c 6f 61 64 2e 64 6c 6c } //01 00  InetLoad.dll
		$a_01_2 = {77 2d 77 2d 77 2d 64 6f 74 2d 63 6f 6d 2e 63 6f 6d 2f 75 70 64 61 74 65 2f 76 65 72 73 69 6f 6e 2e 69 6e 69 } //01 00  w-w-w-dot-com.com/update/version.ini
		$a_01_3 = {74 65 6d 70 5c 5f 75 70 64 61 74 65 2e 65 78 65 } //01 00  temp\_update.exe
		$a_01_4 = {6e 73 45 78 65 63 2e 64 6c 6c } //01 00  nsExec.dll
		$a_01_5 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //01 00  FindNextFileA
		$a_01_6 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  CreateDirectoryA
		$a_01_7 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetWindowsDirectoryA
		$a_01_8 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  SetClipboardData
	condition:
		any of ($a_*)
 
}