
rule TrojanDownloader_Win32_Delf_NJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.NJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 78 64 74 69 63 2e 74 78 74 00 00 ff ff ff ff 0b 00 00 00 64 74 69 63 69 73 61 62 2e 6e 77 00 ff ff ff ff 0b 00 00 00 64 74 69 63 69 73 61 62 2e 6e 74 00 } //01 00 
		$a_01_1 = {24 64 65 6c 69 6d 6f 6c 65 30 2e 62 61 74 00 00 ff ff ff ff 04 00 00 00 3a 74 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}