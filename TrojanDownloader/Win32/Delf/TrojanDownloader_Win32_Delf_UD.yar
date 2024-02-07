
rule TrojanDownloader_Win32_Delf_UD{
	meta:
		description = "TrojanDownloader:Win32/Delf.UD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 45 76 65 72 79 6f 6e 65 00 } //01 00  䔀敶祲湯e
		$a_01_1 = {44 65 6c 65 74 65 64 6c 6c 2e 62 61 74 00 00 00 ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22 } //01 00 
		$a_01_2 = {6a 00 6a 00 68 d8 70 40 00 68 e4 70 40 00 6a 00 e8 05 ff ff ff 68 d8 70 40 00 e8 03 ff ff ff } //01 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}