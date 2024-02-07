
rule TrojanDownloader_Win32_Annia_A{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 82 23 00 00 68 90 01 02 40 00 ff 15 90 20 59 22 da 2d 4e 75 f2 90 00 } //01 00 
		$a_01_1 = {75 67 67 63 3a 2f 2f 34 36 2e 31 34 38 2e 31 39 2e 37 34 2f 6e 69 2e 72 6b 72 } //01 00  uggc://46.148.19.74/ni.rkr
		$a_03_2 = {53 53 6a 03 53 6a 03 53 68 90 01 02 40 00 c7 45 64 90 01 02 40 00 c7 45 68 90 01 02 40 00 c7 45 6c 90 01 02 40 00 89 5d 70 ff 15 90 20 bb a0 ae 1d 90 00 } //00 00 
		$a_00_3 = {78 8d } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Annia_A_2{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 07 04 0d eb 6e 8a 07 3c 4d 7f 1c 0f be c0 50 e8 90 01 04 59 85 c0 74 0e 0f be 07 50 e8 90 01 04 59 85 c0 75 d8 8a 07 3c 6e 90 00 } //01 00 
		$a_03_1 = {75 67 67 63 3a 2f 2f 90 02 10 2f 6e 69 2e 72 6b 72 90 00 } //01 00 
		$a_01_2 = {76 6d 77 61 72 65 00 00 76 69 72 74 75 61 6c 00 71 65 6d 75 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00 
		$a_01_3 = {4a 65 76 67 72 53 76 79 72 } //00 00  JevgrSvyr
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}