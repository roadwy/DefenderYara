
rule TrojanDownloader_Win32_Delf_QU{
	meta:
		description = "TrojanDownloader:Win32/Delf.QU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 46 2e 65 78 65 } //01 00 
		$a_03_1 = {8d 45 f8 ba 90 01 03 00 e8 90 01 03 ff 8b 55 f8 8b 83 0c 03 00 00 8b ce e8 90 01 03 ff 8b c6 e8 90 01 03 ff 8b 83 90 01 01 03 00 00 b2 01 e8 90 01 03 ff 6a 05 68 90 01 03 00 e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}