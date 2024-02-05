
rule TrojanDownloader_Win32_QQHelper_O{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.O,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 66 67 64 61 74 61 2e 63 66 67 00 00 00 44 6c 6c 46 75 6e 00 } //02 00 
		$a_00_1 = {5c 43 6f 6e 66 69 67 5c 4f 72 69 67 69 6e 61 6c 5c 48 6f 6f 6b 2e 69 6e 69 } //02 00 
		$a_00_2 = {4c 6f 67 69 63 5c 48 4c 69 62 2e 64 6c 6c } //02 00 
		$a_00_3 = {51 51 47 61 6d 65 44 6c 2e 65 78 65 } //02 00 
		$a_00_4 = {4d 61 69 6e 4c 6f 67 69 2e 64 6c 6c } //01 00 
		$a_00_5 = {44 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_00_6 = {44 6f 77 6e 54 65 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}