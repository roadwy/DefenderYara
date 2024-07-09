
rule TrojanDownloader_Win32_Renos_HS{
	meta:
		description = "TrojanDownloader:Win32/Renos.HS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {f7 75 0c 8b 45 08 8a 04 02 8a 11 02 01 00 45 fe } //1
		$a_03_1 = {64 8b 1d 30 00 00 00 8a 43 02 0f b6 d8 89 (9d|5d) } //1
		$a_03_2 = {0f b6 c0 83 c0 03 24 fc e8 90 09 04 00 8a 06 (04|2c) } //1
		$a_03_3 = {ff 45 f4 8b 73 04 83 c3 04 89 07 83 c7 04 ff 45 fc 85 f6 75 ?? 83 45 f8 04 ff 45 fc 81 7d f8 } //1
		$a_03_4 = {6a 0c 50 68 00 14 2d 00 90 09 04 00 [0-01] 8d (45|44 24) } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}