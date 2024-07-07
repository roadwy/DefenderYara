
rule TrojanDownloader_Win32_Banload_ZFO_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFO!bit,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //10 Software\Borland\Delphi\Locales
		$a_03_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 02 04 75 72 6c 6d 6f 6e 2e 64 6c 6c 90 00 } //1
		$a_03_2 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 90 02 20 5c 6c 6f 67 2e 74 78 74 90 00 } //1
		$a_01_3 = {00 6e 6f 74 69 66 79 00 } //1 渀瑯晩y
		$a_03_4 = {3a 2f 2f 00 90 02 40 68 74 74 70 00 90 02 30 7a 69 70 00 90 02 30 70 68 70 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=14
 
}