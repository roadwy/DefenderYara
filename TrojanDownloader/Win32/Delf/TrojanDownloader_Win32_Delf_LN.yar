
rule TrojanDownloader_Win32_Delf_LN{
	meta:
		description = "TrojanDownloader:Win32/Delf.LN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00 
		$a_03_1 = {6c 6d 30 32 90 01 04 6d 79 69 65 90 01 0b 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {43 6e 4e 75 6f 49 45 2e 74 6d 70 90 01 09 63 6e 2e 74 6d 70 90 01 0a 63 6e 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}