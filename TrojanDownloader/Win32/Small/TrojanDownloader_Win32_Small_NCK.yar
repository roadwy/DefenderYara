
rule TrojanDownloader_Win32_Small_NCK{
	meta:
		description = "TrojanDownloader:Win32/Small.NCK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_1 = {6d 63 62 6f 6f 2e 63 6f 6d 2f 72 65 74 61 64 70 75 2e 65 78 65 } //01 00 
		$a_01_2 = {6e 61 6d 65 20 66 6f 72 20 25 73 } //01 00 
		$a_01_3 = {61 66 66 49 44 } //01 00 
		$a_00_4 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //00 00 
	condition:
		any of ($a_*)
 
}