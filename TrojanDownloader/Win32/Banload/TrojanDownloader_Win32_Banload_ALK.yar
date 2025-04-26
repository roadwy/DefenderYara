
rule TrojanDownloader_Win32_Banload_ALK{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 64 6c 43 72 79 70 74 90 05 05 01 00 6d 64 6c 44 6f 77 6e 00 } //1
		$a_01_1 = {00 00 62 00 69 00 6e 00 2e 00 62 00 61 00 73 00 65 00 36 00 34 00 00 00 } //1
		$a_00_2 = {5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 76 00 62 00 70 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}