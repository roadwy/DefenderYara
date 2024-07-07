
rule TrojanDownloader_Win32_Banload_LC{
	meta:
		description = "TrojanDownloader:Win32/Banload.LC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 83 f8 02 00 00 e8 90 01 04 8b c6 e8 90 01 04 68 f4 01 00 00 e8 90 01 04 6a 00 8d 55 f8 90 00 } //1
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 6d 64 6c 70 6c 69 74 65 2e 65 78 65 00 } //1
		$a_01_2 = {5c 73 79 73 74 65 6d 33 32 5c 6d 64 6c 78 6c 69 66 65 2e 65 78 65 00 } //1
		$a_01_3 = {67 65 74 5f 77 61 62 73 2e 6a 70 67 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}