
rule TrojanDownloader_Win32_Delf_GM{
	meta:
		description = "TrojanDownloader:Win32/Delf.GM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 69 62 72 61 72 79 6b 2e 63 6f 6d 2f 79 79 } //01 00 
		$a_00_1 = {61 64 76 70 61 63 63 6b 2e 64 6c 6c } //01 00 
		$a_00_2 = {64 65 6c 20 25 30 } //01 00 
		$a_00_3 = {46 4e 54 65 6d 70 65 72 2e 65 78 65 } //01 00 
		$a_03_4 = {dd 5c 24 10 9b a1 90 01 03 00 e8 90 01 03 ff dc 44 24 10 83 c4 f8 dd 1c 24 9b 8d 44 24 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}