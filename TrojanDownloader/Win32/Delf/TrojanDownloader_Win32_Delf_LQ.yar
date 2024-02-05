
rule TrojanDownloader_Win32_Delf_LQ{
	meta:
		description = "TrojanDownloader:Win32/Delf.LQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00 
		$a_03_1 = {64 6f 77 6e 32 90 01 03 2f 6d 79 69 65 2f 70 61 79 75 73 72 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {63 6e 69 65 73 65 74 75 70 2e 74 6d 70 90 01 0b 63 6e 4e 75 49 45 73 2e 74 6d 70 90 01 09 63 6e 4e 49 45 73 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}