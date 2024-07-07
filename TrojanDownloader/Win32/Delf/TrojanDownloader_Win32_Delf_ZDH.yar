
rule TrojanDownloader_Win32_Delf_ZDH{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZDH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {37 41 30 33 34 39 33 38 2d 45 42 44 36 2d 34 46 32 35 2d 39 31 32 44 2d 43 32 36 35 46 30 42 42 44 33 30 35 } //1 7A034938-EBD6-4F25-912D-C265F0BBD305
		$a_01_1 = {4e 65 77 5f 73 74 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_03_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 90 02 0c 5c 49 6e 74 65 6c 5c 57 69 72 65 6c 65 73 73 5c 57 4c 41 4e 50 72 6f 66 69 6c 65 73 5c 90 00 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}