
rule TrojanDownloader_Win32_Banload_YC{
	meta:
		description = "TrojanDownloader:Win32/Banload.YC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {74 00 72 00 69 00 73 00 74 00 65 00 7a 00 61 00 } //01 00  tristeza
		$a_01_1 = {4c 6f 61 64 65 72 00 } //01 00 
		$a_01_2 = {4b 69 6c 6c 50 72 6f 00 } //01 00  楋汬牐o
		$a_01_3 = {56 65 72 73 61 6f 57 69 6e 64 6f 77 73 00 20 } //05 00 
		$a_03_4 = {83 c4 20 66 85 f6 7d 0b 66 81 c6 00 01 0f 80 90 01 02 00 00 8b 55 0c 8b 02 50 ff 15 90 01 04 3b 90 01 01 7d 13 66 8b 4d d0 66 83 c1 01 90 00 } //03 00 
		$a_03_5 = {75 38 c7 45 fc 90 01 01 00 00 00 68 30 75 00 00 e8 90 01 04 ff 15 90 01 04 c7 45 fc 90 01 01 00 00 00 ff 15 90 01 04 c7 45 fc 90 01 01 00 00 00 e8 90 01 04 66 a3 90 01 04 eb b7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}