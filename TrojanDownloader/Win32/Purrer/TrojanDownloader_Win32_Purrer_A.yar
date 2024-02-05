
rule TrojanDownloader_Win32_Purrer_A{
	meta:
		description = "TrojanDownloader:Win32/Purrer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 } //01 00 
		$a_01_1 = {68 80 00 00 00 f3 ab 66 ab aa 8d 45 80 33 f6 50 6a 0a 68 00 04 00 00 ff 15 } //01 00 
		$a_01_2 = {8a 5d 0c 83 c6 04 32 d8 8b 06 88 19 41 83 f8 ff 75 ee } //00 00 
	condition:
		any of ($a_*)
 
}