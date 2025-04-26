
rule TrojanDownloader_Win32_Delf_HE{
	meta:
		description = "TrojanDownloader:Win32/Delf.HE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 30 37 35 30 63 61 72 2e 6e 65 74 2e 63 6e 2f 63 72 61 63 6b 73 61 66 65 2f [0-08] 2e 65 78 65 } //1
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}