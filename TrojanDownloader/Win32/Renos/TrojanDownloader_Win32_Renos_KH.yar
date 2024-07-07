
rule TrojanDownloader_Win32_Renos_KH{
	meta:
		description = "TrojanDownloader:Win32/Renos.KH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c9 51 51 51 6a 06 ff d0 68 90 01 04 68 90 01 04 e8 90 00 } //1
		$a_03_1 = {68 00 14 2d 00 ff 74 24 90 01 01 ff 15 90 01 03 00 90 00 } //1
		$a_03_2 = {8b 44 24 08 23 c8 89 0d 90 01 03 00 8a 0d 90 01 03 00 22 0d 90 01 03 00 88 0d 90 01 03 00 8b 0d 90 01 03 00 03 c1 66 a3 90 01 03 00 0f bf c0 c3 90 00 } //1
		$a_03_3 = {04 5a 0f b6 c0 83 c0 03 23 c6 e8 90 01 04 8b c4 57 50 e8 90 01 04 8b f8 57 e8 90 01 04 83 c4 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}