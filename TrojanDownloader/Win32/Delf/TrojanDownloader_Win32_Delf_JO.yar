
rule TrojanDownloader_Win32_Delf_JO{
	meta:
		description = "TrojanDownloader:Win32/Delf.JO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 22 70 72 6f 67 72 61 6d 6d 22 } //01 00 
		$a_01_1 = {6d 79 6e 65 77 73 70 61 67 65 73 2e 63 6f 6d } //01 00 
		$a_01_2 = {64 77 30 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}