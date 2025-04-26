
rule TrojanDownloader_Win32_Renos_JT{
	meta:
		description = "TrojanDownloader:Win32/Renos.JT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 04 19 88 03 } //1
		$a_01_1 = {0f 01 4c 24 } //1
		$a_01_2 = {68 58 4d 56 } //1 hXMV
		$a_03_3 = {0f b6 c0 83 c0 ?? 24 } //1
		$a_00_4 = {77 67 65 74 20 33 2e 30 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}