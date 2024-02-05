
rule TrojanDownloader_Win32_Banload_BFP{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 64 6f 62 65 50 6c 61 79 90 02 10 55 53 45 52 50 52 4f 46 49 4c 45 90 00 } //01 00 
		$a_01_1 = {2f 6e 6f 74 69 66 79 2e 70 68 70 } //01 00 
		$a_03_2 = {4d 69 63 72 6f 73 6f 66 74 53 51 4c 90 01 0c 2e 7a 69 70 90 01 0c 2e 76 62 73 90 00 } //01 00 
		$a_03_3 = {ff 75 fc 8d 45 90 01 01 ba 06 00 00 00 e8 90 09 24 00 8d 55 90 01 01 b8 90 01 04 e8 90 01 02 ff ff ff 75 90 01 01 68 90 01 04 68 90 01 04 68 90 01 04 68 90 00 } //01 00 
		$a_03_4 = {ba 0f 00 00 00 8b c3 e8 90 01 02 ff ff 8d 45 90 01 01 ba 90 01 04 e8 90 01 03 ff 8b 55 90 01 01 8b 83 90 01 01 03 00 00 e8 90 01 03 ff 8d 4d 90 01 01 ba 14 00 00 00 8b c3 e8 90 01 02 ff ff 8d 45 90 01 01 ba 90 01 04 e8 90 01 03 ff 8b 55 90 00 } //00 00 
		$a_00_5 = {80 10 00 } //00 d5 
	condition:
		any of ($a_*)
 
}