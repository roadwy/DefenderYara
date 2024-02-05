
rule TrojanDownloader_Win32_Delf_RAW{
	meta:
		description = "TrojanDownloader:Win32/Delf.RAW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 6e 79 68 6f 6d 62 2e 37 2f 33 21 2b 62 6c 6c 73 60 77 68 61 6d 66 3a 23 4c 50 48 46 21 35 2f 33 3a 23 56 6a 6f 67 6e 74 72 23 4f 57 21 36 2f 32 3a 23 64 6d 28 23 4e 73 64 71 60 23 39 2d 34 } //01 00 
		$a_01_1 = {46 2d 53 74 6f 70 57 2e 65 78 65 } //01 00 
		$a_01_2 = {62 64 6f 65 73 72 76 2e 65 78 65 } //01 00 
		$a_01_3 = {62 64 6d 63 6f 6e 2e 65 78 65 } //01 00 
		$a_02_4 = {89 45 f8 33 c0 55 68 90 01 04 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 8b 90 01 01 e8 90 01 04 50 8b 45 f8 50 e8 90 01 04 89 45 f4 33 c0 55 68 90 01 04 64 ff 30 64 89 20 56 68 00 04 00 00 8d 85 f0 fb ff ff 50 8b 45 f4 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}