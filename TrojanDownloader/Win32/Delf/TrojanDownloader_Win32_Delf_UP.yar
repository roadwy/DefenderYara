
rule TrojanDownloader_Win32_Delf_UP{
	meta:
		description = "TrojanDownloader:Win32/Delf.UP,SIGNATURE_TYPE_PEHSTR,17 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6f 6c 6d 65 6c 69 66 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_2 = {64 72 69 76 65 72 73 5c 76 70 6c 6f 73 65 2e 65 78 65 } //01 00 
		$a_01_3 = {4e 50 4d 49 53 2e 45 58 45 } //01 00 
		$a_01_4 = {58 69 61 6f 79 65 7a 69 5f 43 6f 6f 6c 4d 65 } //00 00 
	condition:
		any of ($a_*)
 
}