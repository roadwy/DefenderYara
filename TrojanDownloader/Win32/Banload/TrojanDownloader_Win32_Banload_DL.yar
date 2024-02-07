
rule TrojanDownloader_Win32_Banload_DL{
	meta:
		description = "TrojanDownloader:Win32/Banload.DL,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 72 65 67 73 76 72 33 32 20 2f 73 } //01 00  \regsvr32 /s
		$a_00_1 = {43 68 65 63 6b 45 78 65 53 69 67 6e 61 74 75 72 65 73 } //01 00  CheckExeSignatures
		$a_00_2 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //01 00  TaskbarCreated
		$a_00_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 44 6f 77 6e 6c 6f 61 64 } //0a 00  \Software\Microsoft\Internet Explorer\Download
		$a_02_5 = {64 ff 30 64 89 20 ba 02 00 00 80 8b 45 fc e8 90 01 04 8d 45 f8 ba 90 01 04 e8 90 01 04 b1 01 8b 55 f8 8b 45 fc e8 90 01 04 84 c0 0f 84 90 01 02 00 00 ba 90 01 04 8b 45 fc e8 90 01 04 84 c0 0f 85 90 01 02 00 00 ba 02 00 00 80 8b 45 fc e8 90 01 04 8d 45 f8 ba 90 01 04 e8 90 01 04 b1 01 8b 55 f8 8b 45 fc e8 90 01 04 84 c0 0f 84 90 01 02 00 00 ba 90 01 04 8b 45 fc e8 90 01 04 84 c0 0f 85 90 01 02 00 00 8d 45 f0 e8 90 01 04 ff 75 f0 68 90 01 04 68 90 01 04 8d 45 f4 ba 03 00 00 00 e8 90 01 04 8b 45 f4 e8 90 01 04 68 90 01 04 ff 75 f4 68 90 01 04 8d 45 ec ba 03 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}