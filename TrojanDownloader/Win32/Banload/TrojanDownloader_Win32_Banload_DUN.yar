
rule TrojanDownloader_Win32_Banload_DUN{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 } //01 00 
		$a_00_1 = {2e 74 78 74 } //01 00 
		$a_00_2 = {2a 2e 6d 62 6f 78 } //01 00 
		$a_00_3 = {2a 2e 77 61 62 } //01 00 
		$a_00_4 = {2a 2e 6d 62 78 } //01 00 
		$a_00_5 = {2a 2e 65 6d 6c } //01 00 
		$a_00_6 = {2a 2e 74 62 62 } //01 00 
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_02_8 = {33 ff 8d 45 e0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc e8 90 01 02 fe ff 8b 4d e0 8d 45 e4 ba 90 01 02 41 00 e8 90 01 02 fe ff 8b 45 e4 e8 90 01 02 fe ff 89 45 f0 be 03 00 00 00 8d 45 d8 50 b9 02 00 00 00 8b d6 8b 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_DUN_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUN,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 63 72 73 73 2e 65 78 65 00 } //01 00 
		$a_00_1 = {2f 73 79 73 2e 65 78 65 00 } //01 00 
		$a_00_2 = {2f 64 6f 73 2e 65 78 65 00 } //0a 00 
		$a_02_3 = {64 ff 30 64 89 20 33 d2 b8 90 01 04 e8 90 01 02 ff ff 8d 45 e8 e8 90 01 02 ff ff ff 75 e8 68 90 01 04 68 90 01 04 8d 45 ec ba 03 00 00 00 e8 90 01 02 ff ff 8b 55 ec b8 90 01 04 e8 90 01 02 ff ff 84 c0 74 2c 8d 45 e0 e8 90 01 02 ff ff ff 75 e0 68 90 01 04 68 90 01 04 8d 45 e4 ba 03 00 00 00 e8 90 01 02 ff ff 8b 45 e4 33 d2 e8 90 01 02 ff ff 8d 45 d8 e8 90 01 02 ff ff ff 75 d8 68 90 01 04 68 90 01 04 8d 45 dc ba 03 00 00 00 e8 90 01 02 ff ff 8b 55 dc b8 90 01 04 e8 90 01 02 ff ff 84 c0 74 2c 8d 45 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}