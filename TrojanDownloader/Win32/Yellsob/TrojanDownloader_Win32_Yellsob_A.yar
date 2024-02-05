
rule TrojanDownloader_Win32_Yellsob_A{
	meta:
		description = "TrojanDownloader:Win32/Yellsob.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 2e 53 8b 5c 24 18 57 8a 44 14 10 8a 0c 1e 32 c8 8d 7c 24 10 88 0c 1e 83 c9 ff 33 c0 f2 ae f7 d1 8d 42 01 49 33 d2 f7 f1 46 3b f5 72 da } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Yellsob_A_2{
	meta:
		description = "TrojanDownloader:Win32/Yellsob.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 2a 8b 4c 24 0c 53 8b 5c 24 18 55 8b 6c 24 20 56 8b 74 24 14 2b f1 8a 04 0e 32 04 1a 88 01 8d 42 01 99 f7 fd 41 4f 75 ee } //01 00 
		$a_01_1 = {6a 04 52 68 23 e2 22 00 50 56 ff 15 } //01 00 
		$a_03_2 = {68 30 75 00 00 8b f0 ff d7 6a 00 6a 00 6a 10 56 ff 15 90 01 04 6a 00 6a 00 6a 10 56 ff 15 90 00 } //01 00 
		$a_01_3 = {4d 61 79 61 42 61 62 79 44 6c 6c 2e 64 6c 6c 00 43 6c 65 61 72 41 56 00 44 6f 57 6f 72 6b } //00 00 
	condition:
		any of ($a_*)
 
}