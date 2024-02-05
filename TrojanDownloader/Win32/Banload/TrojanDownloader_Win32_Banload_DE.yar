
rule TrojanDownloader_Win32_Banload_DE{
	meta:
		description = "TrojanDownloader:Win32/Banload.DE,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_00_1 = {77 00 69 00 6e 00 64 00 69 00 72 00 } //01 00 
		$a_00_2 = {5c 00 6d 00 73 00 6e 00 6d 00 73 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_3 = {3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c } //05 00 
		$a_02_4 = {55 8b ec 83 ec 08 68 36 11 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 53 56 57 89 65 f8 c7 45 fc 90 01 01 11 40 00 8b 55 0c 8b 3d 8c 10 40 00 33 f6 8d 4d e4 89 75 ec 89 75 e4 89 75 e0 89 75 dc 89 75 d8 ff d7 8b 55 10 8d 4d e0 ff d7 8b 45 e0 8b 3d a4 10 40 00 56 56 8d 4d d8 50 51 ff d7 8b 55 e4 50 8d 45 dc 52 50 ff d7 50 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}