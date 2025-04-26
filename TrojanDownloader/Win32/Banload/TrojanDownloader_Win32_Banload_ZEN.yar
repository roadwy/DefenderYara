
rule TrojanDownloader_Win32_Banload_ZEN{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 20 6c 69 6e 6b 20 3a 00 } //1
		$a_01_1 = {42 61 7a 61 61 72 20 4c 69 6e 6b 20 3a 00 } //1
		$a_01_2 = {74 65 78 74 69 69 6e 66 6f 00 } //1 整瑸楩普o
		$a_01_3 = {62 61 7a 61 72 20 66 75 63 6b 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}