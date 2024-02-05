
rule TrojanDownloader_Win32_Banload_ANL{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 90 01 04 83 f8 07 75 1c 6a 01 e8 90 00 } //01 00 
		$a_01_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4 } //01 00 
		$a_03_2 = {46 eb 05 be 01 00 00 00 b8 90 01 04 0f b6 44 30 ff 33 d8 8d 45 90 01 01 50 89 5d 90 01 01 c6 45 90 01 01 00 8d 55 90 1b 02 90 00 } //01 00 
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //01 00 
		$a_01_4 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}