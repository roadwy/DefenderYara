
rule TrojanDownloader_Win32_Bredolab_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Bredolab.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 e2 0c 8b 5f 08 8b 44 24 10 03 c1 8a 1c 1e 32 da 30 18 46 3b 37 72 02 33 f6 } //02 00 
		$a_01_1 = {6a 01 8d 44 11 ff 5a 80 e3 0c 2b d1 8b 4e 08 8a 4c 39 ff 32 08 32 cb 4f 88 08 75 02 8b 3e } //02 00 
		$a_01_2 = {8b 75 08 81 7d 0c f8 00 00 00 8b 46 3c 8d 3c 30 0f 82 f9 00 00 00 81 3f 50 45 00 00 0f 85 ed 00 00 00 3b c3 0f 8e e5 00 00 00 6a 04 68 00 30 00 00 } //01 00 
		$a_01_3 = {4d 61 67 69 63 2d 4e 75 6d 62 65 72 3a } //01 00 
		$a_01_4 = {45 6e 74 69 74 79 2d 49 6e 66 6f 3a } //02 00 
		$a_01_5 = {2f 6c 6f 61 64 65 72 62 62 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}