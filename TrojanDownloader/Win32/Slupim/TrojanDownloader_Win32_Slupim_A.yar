
rule TrojanDownloader_Win32_Slupim_A{
	meta:
		description = "TrojanDownloader:Win32/Slupim.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 04 00 "
		
	strings :
		$a_02_0 = {83 44 24 10 01 e9 0c ff ff ff 89 6c 24 10 89 6c 24 14 89 6c 24 18 89 6c 24 24 8b 6c 24 28 68 90 01 02 00 10 55 33 db e8 90 00 } //04 00 
		$a_03_1 = {50 89 5c 24 1c 89 5c 24 20 89 7c 24 90 01 01 89 7c 24 30 e8 90 01 02 00 00 8b f0 83 c4 08 3b f7 74 3d 68 90 01 02 00 10 ff d5 90 00 } //01 00 
		$a_01_2 = {53 52 56 3a 00 } //01 00 
		$a_01_3 = {53 4c 50 3a 00 } //01 00 
		$a_01_4 = {4d 4f 44 3a 00 } //01 00 
		$a_01_5 = {6d 6f 64 3d 25 73 26 69 64 3d 25 73 5f 25 64 26 75 70 3d 25 64 26 6d 69 64 3d 25 73 00 } //01 00 
		$a_01_6 = {68 74 74 70 3a 2f 2f 25 73 2f 62 74 2e 70 68 70 3f 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}