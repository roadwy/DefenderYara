
rule TrojanDownloader_Win32_Delf_TE{
	meta:
		description = "TrojanDownloader:Win32/Delf.TE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 40 30 50 e8 90 01 04 8d 55 fc b8 20 00 00 00 e8 90 01 04 8b 55 fc 8d 83 90 01 01 03 00 00 b9 90 01 04 e8 90 01 04 8d 83 90 01 01 03 00 00 90 00 } //01 00 
		$a_03_1 = {8b 00 8b 40 30 50 e8 90 01 04 8d 55 fc b8 20 00 00 00 e8 90 01 04 ff 75 fc 68 90 01 04 68 90 01 04 8d 83 28 03 00 00 ba 03 00 00 00 90 00 } //01 00 
		$a_00_2 = {2f 56 45 52 59 53 49 4c 45 4e 54 20 2f 53 50 2d } //01 00 
		$a_00_3 = {66 69 6c 65 6e 6f 6c 6a 61 2e 63 6f 6d 2f 73 70 6f 6e } //01 00 
		$a_00_4 = {43 00 6f 00 64 00 65 00 3a 00 20 00 25 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}