
rule TrojanDownloader_Win32_VB_GBX{
	meta:
		description = "TrojanDownloader:Win32/VB.GBX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 58 45 43 55 54 41 } //01 00  EXECUTA
		$a_01_1 = {50 55 58 41 } //01 00  PUXA
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_02_3 = {55 8b ec 83 ec 0c 68 90 01 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 18 53 56 57 89 65 f4 c7 45 f8 90 01 04 33 db 89 5d fc 8b 75 08 56 8b 06 ff 50 04 8b 3d 90 01 04 ba 90 01 04 8d 4d e4 89 5d e8 89 5d e4 89 5d e0 ff d7 ba 90 01 04 8d 4d e8 ff d7 8b 0e 8d 55 e0 52 8d 45 e4 8d 55 e8 50 52 56 ff 91 f8 06 00 00 3b c3 7d 12 68 f8 06 00 00 68 90 01 04 56 50 90 00 } //01 00 
		$a_02_4 = {55 8b ec 83 ec 0c 68 90 01 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 90 01 01 53 56 57 89 65 f4 c7 45 f8 90 01 04 8b 7d 08 8b c7 83 e0 01 89 45 fc 83 e7 fe 57 89 7d 08 8b 0f ff 51 04 a1 90 01 04 c7 45 e8 00 00 00 00 85 c0 75 10 68 90 01 04 68 90 01 04 ff 15 90 01 04 8b 35 90 01 04 56 8b 16 ff 92 b4 02 00 00 85 c0 db e2 7d 16 8b 1d 90 01 04 68 b4 02 00 00 68 90 01 04 56 50 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}