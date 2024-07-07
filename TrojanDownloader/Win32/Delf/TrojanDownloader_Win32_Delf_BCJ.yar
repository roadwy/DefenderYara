
rule TrojanDownloader_Win32_Delf_BCJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.BCJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_03_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 63 6b 73 65 6e 2e 63 6f 6d 2f 7a 62 2f 75 72 6c 90 02 01 2e 74 78 74 90 00 } //1
		$a_01_2 = {77 65 62 3d 00 00 00 00 ff ff ff ff 04 00 00 00 75 72 6c 3d 00 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 00 00 00 ff ff ff ff 04 00 00 00 73 72 73 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}