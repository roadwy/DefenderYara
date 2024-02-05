
rule TrojanDownloader_Win32_Delf_EF{
	meta:
		description = "TrojanDownloader:Win32/Delf.EF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6e 4a 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 ff ff ff ff 09 00 00 00 5c 79 62 7f } //01 00 
		$a_01_1 = {58 63 6e 67 67 4e 73 6e 68 7e 7f 6e 4a 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}