
rule TrojanDownloader_Win32_Delf_DT{
	meta:
		description = "TrojanDownloader:Win32/Delf.DT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 6a 00 8b 90 01 02 50 e8 90 01 04 6a 00 8d 90 01 02 50 68 03 01 00 00 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 00 73 69 74 65 3a 00 00 00 53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 64 6f 77 6e 3a 00 00 00 ff ff ff ff 04 00 00 00 54 65 6d 70 00 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}