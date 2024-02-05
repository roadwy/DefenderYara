
rule TrojanDownloader_Win32_Delf_GC{
	meta:
		description = "TrojanDownloader:Win32/Delf.GC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 69 6e 6c 6f 67 6f 6e } //01 00 
		$a_00_1 = {64 6f 77 6e 5f 31 5f 66 69 6c 65 } //01 00 
		$a_00_2 = {64 6f 77 6e 20 63 6f 6e 66 3a } //01 00 
		$a_00_3 = {57 41 43 4c 45 76 65 6e 74 4c 6f 67 6f 6e } //01 00 
		$a_00_4 = {70 72 6f 74 65 63 74 20 73 65 63 6f 6e 64 3a } //01 00 
		$a_00_5 = {64 6f 77 6e 20 66 69 6c 65 7a } //01 00 
		$a_00_6 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_00_7 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a } //01 00 
		$a_00_8 = {73 70 69 73 6f 6b 20 6f 6b } //01 00 
		$a_02_9 = {50 6a 00 6a 00 68 90 01 04 6a 00 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}