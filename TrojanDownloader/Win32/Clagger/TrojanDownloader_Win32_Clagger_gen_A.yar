
rule TrojanDownloader_Win32_Clagger_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Clagger.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 07 00 00 04 00 "
		
	strings :
		$a_00_0 = {54 5a 74 55 66 4e 5d 64 56 73 73 46 6f 75 44 70 6f 55 73 70 6d 54 66 75 5d 74 46 73 77 6a 44 66 54 5d 54 49 62 73 } //04 00  TZtUfN]dVssFouDpoUspmTfu]tFswjDfT]TIbs
		$a_02_1 = {05 39 58 f8 7e 18 8a 04 06 8d 4d e4 fe c8 50 56 e8 90 01 02 00 00 8b 45 e4 46 3b 70 f8 7c e8 8d 4d 90 00 } //03 00 
		$a_02_2 = {40 00 8d 44 24 54 6a 4b 50 e8 90 01 02 ff ff 8a 44 24 5c 83 c4 10 3c 68 74 08 3c 48 0f 85 90 00 } //02 00 
		$a_00_3 = {67 6f 74 6f 20 31 00 69 66 20 65 78 69 73 74 20 } //02 00 
		$a_00_4 = {00 00 3d f4 01 00 00 8d 4d c8 73 54 e8 } //02 00 
		$a_00_5 = {53 8a 1c 08 80 f3 58 88 1c 08 40 3b c2 7c f2 5b c3 90 64 a1 00 00 00 00 6a ff 68 e8 23 40 00 50 } //01 00 
		$a_00_6 = {70 68 70 00 65 78 65 00 } //00 00  桰p硥e
	condition:
		any of ($a_*)
 
}