
rule TrojanDownloader_Win32_VB_BS{
	meta:
		description = "TrojanDownloader:Win32/VB.BS,SIGNATURE_TYPE_PEHSTR,33 00 33 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //0a 00  MSVBVM60.DLL
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 5f 70 72 6f 67 72 65 73 73 } //0a 00  download_progress
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_3 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 4b 00 41 00 56 00 53 00 74 00 61 00 72 00 74 00 } //0a 00  cmd /c net stop KAVStart
		$a_01_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 33 00 36 00 30 00 53 00 61 00 66 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  taskkill /f /im 360Safe.exe
		$a_01_5 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 57 00 65 00 62 00 5c 00 49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 52 00 2e 00 45 00 58 00 45 00 } //01 00  C:\WINDOWS\Web\IEXPLORER.EXE
		$a_01_6 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 53 00 65 00 74 00 75 00 70 00 5c 00 49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 52 00 2e 00 45 00 58 00 45 00 } //00 00  C:\WINDOWS\system32\Setup\IEXPLORER.EXE
	condition:
		any of ($a_*)
 
}