
rule TrojanDownloader_Win32_Zlob_BBD{
	meta:
		description = "TrojanDownloader:Win32/Zlob.BBD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 01 c6 85 90 01 02 ff ff 52 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 6b c6 85 90 01 02 ff ff 49 c6 85 90 01 02 ff ff 45 c6 85 90 01 02 ff ff 2f c6 85 90 01 02 ff ff 31 c6 85 90 01 02 ff ff 2e c6 85 90 01 02 ff ff 30 90 00 } //01 00 
		$a_00_1 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73 } //01 00  EnumProcesses
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 } //01 00 
		$a_00_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}