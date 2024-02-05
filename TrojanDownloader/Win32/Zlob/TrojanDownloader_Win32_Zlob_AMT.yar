
rule TrojanDownloader_Win32_Zlob_AMT{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AMT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b c7 45 fc fe ff ff ff 33 c0 81 7d e4 68 58 4d 56 0f 94 c0 } //01 00 
		$a_03_1 = {41 00 75 28 b9 90 01 01 00 00 00 0f 31 69 c0 35 4e 5a 01 83 c0 01 89 44 24 08 0f 31 69 c0 35 4e 5a 01 83 c0 01 89 44 24 48 e9 90 00 } //03 00 
		$a_01_2 = {2f 63 6f 6e 66 69 72 6d 2e 70 68 70 3f 61 69 64 3d 25 6c 75 26 73 61 69 64 3d 25 6c 75 26 6d 61 63 3d 25 73 26 68 61 73 68 3d 25 73 26 6d 6e 3d 25 6c 75 00 } //01 00 
		$a_01_3 = {00 2e 6d 69 78 63 72 74 00 45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}