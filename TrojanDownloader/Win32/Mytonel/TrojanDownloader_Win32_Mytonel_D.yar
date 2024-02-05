
rule TrojanDownloader_Win32_Mytonel_D{
	meta:
		description = "TrojanDownloader:Win32/Mytonel.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 56 6a 08 68 09 02 00 00 51 ff d7 8b 56 90 01 01 6a 4f 6a 08 68 0a 02 00 00 52 ff d7 8b 46 90 01 01 6a 4b 6a 08 68 0b 02 00 00 50 ff d7 8b 4e 90 01 01 6a 53 6a 08 68 0c 02 00 00 51 ff d7 90 00 } //01 00 
		$a_01_1 = {75 20 ff d5 83 f8 20 75 19 ff d5 83 f8 20 75 12 68 f4 01 00 00 ff 15 } //01 00 
		$a_01_2 = {6a 00 68 80 ee 36 00 6a 02 51 ff d7 8b 56 1c 6a 00 68 80 ee 36 00 6a 03 52 ff d7 } //02 00 
		$a_01_3 = {00 57 61 74 63 68 44 65 73 6b 74 6f 70 20 46 69 6e 64 46 69 6c 65 00 00 00 2a 00 2e 00 2a 00 00 00 2a 00 2e 00 6c 00 6e 00 6b 00 00 00 43 57 61 74 63 68 44 65 73 6b 74 6f 70 20 52 75 6e 00 } //02 00 
		$a_01_4 = {00 44 4c 4c 69 73 74 2e 69 6e 69 00 } //00 00 
		$a_00_5 = {80 10 00 } //00 3e 
	condition:
		any of ($a_*)
 
}