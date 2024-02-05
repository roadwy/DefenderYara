
rule TrojanDownloader_Win32_Bredolab_AC{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 54 24 08 8a 18 80 f3 90 01 01 81 e3 ff 00 00 00 33 d9 88 1a 41 42 40 83 f9 10 75 e9 90 00 } //01 00 
		$a_01_1 = {80 fa 24 75 61 8d 58 01 ba fe 00 00 00 2b d0 2b d3 72 53 42 80 3c 1e 3a 75 48 } //01 00 
		$a_01_2 = {7c 1a 41 33 d2 8b 1c 24 8d 3c 13 8a 1c 30 30 1f 46 83 fe 10 75 02 } //01 00 
		$a_03_3 = {75 11 8b c3 e8 90 01 04 83 f8 01 75 05 bf 02 00 00 00 83 ff 02 75 90 01 01 6a 00 6a 04 90 00 } //01 00 
		$a_01_4 = {3d 7b 8d a8 f2 } //00 00 
	condition:
		any of ($a_*)
 
}