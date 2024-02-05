
rule TrojanDownloader_Win32_Delf_LK{
	meta:
		description = "TrojanDownloader:Win32/Delf.LK,SIGNATURE_TYPE_PEHSTR_EXT,19 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00 
		$a_00_1 = {45 72 72 6f 2e 2e 20 41 72 71 75 69 76 6f 20 63 6f 72 72 6f 6d 70 69 64 6f } //02 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 20 2e 63 6f 6d 2e 62 72 2f 90 02 08 2e 6a 70 67 90 00 } //01 00 
		$a_00_3 = {00 73 69 73 73 2e 65 78 65 00 } //01 00 
		$a_00_4 = {00 73 6d 73 73 2e 65 78 65 00 } //01 00 
		$a_00_5 = {00 74 75 72 62 6f 5f 64 62 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}