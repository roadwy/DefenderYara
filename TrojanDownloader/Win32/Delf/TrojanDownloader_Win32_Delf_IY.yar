
rule TrojanDownloader_Win32_Delf_IY{
	meta:
		description = "TrojanDownloader:Win32/Delf.IY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 62 6f 7a 69 6d 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 6e 6f 68 6f 74 2e 6a 70 67 } //01 00 
		$a_01_1 = {61 76 61 74 61 72 2e 6a 70 67 } //01 00 
		$a_01_2 = {73 61 74 70 6c 67 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}