
rule TrojanDownloader_Win32_Delf_QW{
	meta:
		description = "TrojanDownloader:Win32/Delf.QW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 00 ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00 ff ff ff ff 01 00 00 00 2f 00 00 00 ff ff ff ff 0e 00 00 00 64 31 2e 64 6f 77 6e 78 69 61 2e 6e 65 74 } //01 00 
		$a_01_1 = {e8 6e 5b fd ff 83 f8 01 1b db 43 c6 45 d7 00 84 db 75 3c 8b 55 ec b8 28 fe 44 00 e8 83 53 fb ff } //00 00 
	condition:
		any of ($a_*)
 
}