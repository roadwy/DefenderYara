
rule TrojanDownloader_Win32_Horst_J{
	meta:
		description = "TrojanDownloader:Win32/Horst.J,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 e4 f8 81 ec 34 03 00 00 a1 90 01 04 53 56 57 33 f6 89 84 24 3c 03 00 00 33 c0 89 74 24 68 b9 b2 00 00 00 8d 7c 24 6c f3 ab b9 11 00 00 00 8d 7c 24 20 f3 ab 8d 4c 24 0c 51 8b 4d 08 89 44 24 10 8d 54 24 24 52 56 56 89 44 24 20 89 44 24 24 6a 04 89 44 24 2c 8b 45 18 50 56 56 51 56 89 74 24 44 c7 44 24 48 44 00 00 00 66 c7 44 24 78 05 00 ff 15 90 01 04 85 c0 75 1f 56 ff 15 90 01 04 b8 01 00 00 00 8b 8c 24 3c 03 00 00 e8 90 01 04 5f 5e 5b 8b e5 5d c3 ff 15 90 01 04 8b 1d 90 01 04 56 ff d3 56 ff 55 1c 8b 55 14 8b f0 56 52 90 00 } //01 00 
		$a_01_1 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //01 00  InternetCloseHandle
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_4 = {4f 70 65 6e 4d 75 74 65 78 41 } //01 00  OpenMutexA
		$a_01_5 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_02_6 = {8b 54 24 10 52 ff 15 90 01 04 83 f8 ff 75 18 b8 07 00 00 00 8b 8c 24 3c 03 00 00 e8 90 01 04 5f 5e 5b 8b e5 5d c3 8b 35 90 01 04 ff d6 8b 45 10 85 c0 74 0d 8b 44 24 10 6a ff 50 ff 15 90 01 04 ff d6 8b 8c 24 3c 03 00 00 33 c0 e8 90 01 04 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}