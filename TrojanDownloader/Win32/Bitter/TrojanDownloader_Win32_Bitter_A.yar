
rule TrojanDownloader_Win32_Bitter_A{
	meta:
		description = "TrojanDownloader:Win32/Bitter.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 2f 2f 68 65 61 6c 74 68 6e 65 2f 61 63 63 65 70 74 2e 70 68 70 } //01 00  GET ///healthne/accept.php
		$a_01_1 = {37 66 35 65 64 38 35 64 2d 36 38 32 38 2d 34 66 39 32 2d 38 35 38 63 2d 66 34 30 62 30 61 63 36 38 31 33 38 } //01 00  7f5ed85d-6828-4f92-858c-f40b0ac68138
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}