
rule TrojanDownloader_Win32_Delf_IR{
	meta:
		description = "TrojanDownloader:Win32/Delf.IR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 40 00 85 d2 74 90 01 01 66 83 7a f6 02 74 90 01 01 e9 90 01 04 8b 4a f8 41 7e 90 01 01 f0 ff 42 f8 87 10 85 d2 74 90 01 01 8b 4a f8 49 7c 90 01 01 f0 ff 4a f8 75 90 01 01 8d 42 f4 e8 90 00 } //01 00 
		$a_00_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  .exe -runservice
		$a_00_3 = {2f 66 69 6c 74 65 63 74 2e 70 68 70 } //00 00  /filtect.php
	condition:
		any of ($a_*)
 
}