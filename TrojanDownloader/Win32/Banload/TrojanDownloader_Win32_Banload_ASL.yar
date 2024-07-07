
rule TrojanDownloader_Win32_Banload_ASL{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 0f b7 44 70 fe 33 c3 89 45 dc 3b 7d dc 7c 90 01 01 8b 45 dc 05 ff 00 00 00 2b c7 89 45 dc eb 90 00 } //1
		$a_03_1 = {8d 45 f0 ba 90 01 04 e8 90 01 04 8d 45 f4 33 d2 e8 90 01 04 8b 45 f0 85 c0 74 90 01 01 8b d0 83 ea 0a 66 83 3a 02 90 00 } //1
		$a_03_2 = {89 03 8b 03 8b 10 ff 52 44 8d 4d fc ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 55 fc 8b 03 8b 08 ff 51 38 8d 4d f8 ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 55 f8 8b 03 8b 08 ff 51 38 8d 4d f4 ba 90 01 04 b8 90 01 04 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}