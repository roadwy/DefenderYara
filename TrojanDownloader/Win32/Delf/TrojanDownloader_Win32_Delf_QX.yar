
rule TrojanDownloader_Win32_Delf_QX{
	meta:
		description = "TrojanDownloader:Win32/Delf.QX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 2e 77 69 6e 62 6b 32 63 6c 2e 63 6f 6d 2f 62 68 6f 6e 2f 77 69 6e 62 6b 32 63 6c 32 2e 64 6c 6c } //01 00 
		$a_01_1 = {64 6f 77 6e 2e 77 69 6e 73 6f 66 74 31 2e 63 6f 6d 2f 73 65 74 75 70 2f 70 30 30 33 5f 62 6b 32 2f 73 65 74 75 70 2e 65 78 65 } //01 00 
		$a_01_2 = {64 6f 77 6e 2e 77 69 6e 62 6b 32 63 6c 2e 63 6f 6d 2f 49 6e 73 74 61 6c 6c 5f 66 72 65 65 7a 6f 6e 65 5f 73 65 61 72 63 68 5f 31 38 30 5f 42 2e 65 78 65 } //01 00 
		$a_01_3 = {77 69 6e 2e 77 69 6e 62 6b 32 63 6c 2e 63 6f 6d 2f 6d 64 2f 63 68 2e 68 74 6d 6c 3f 4d 41 43 3d } //00 00 
	condition:
		any of ($a_*)
 
}