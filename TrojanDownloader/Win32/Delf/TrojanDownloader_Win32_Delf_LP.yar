
rule TrojanDownloader_Win32_Delf_LP{
	meta:
		description = "TrojanDownloader:Win32/Delf.LP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00 
		$a_03_1 = {64 6f 77 6e 32 90 01 03 2f 6d 79 69 65 2f 90 01 07 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {63 6e 73 65 74 75 70 73 2e 74 6d 70 90 01 0c 63 6e 49 45 2e 74 6d 70 90 01 0c 63 6e 49 45 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}