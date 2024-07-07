
rule TrojanDownloader_Win32_Farfli_PH_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.PH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 38 00 56 8b f1 8b c8 74 0c 8d 9b 00 00 00 00 41 80 39 00 75 fa 8a 16 88 11 41 46 84 d2 75 f6 5e c3 } //1
		$a_03_1 = {4b c6 44 24 90 01 01 6f c6 44 24 90 01 01 74 c6 44 24 90 01 01 68 c6 44 24 90 01 01 65 c6 44 24 90 01 01 72 c6 44 24 90 00 } //1
		$a_01_2 = {0f b7 06 8b e8 81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 0d 8b 6c 24 14 25 ff 0f 00 00 03 c7 01 28 8b 41 04 83 e8 08 42 d1 e8 83 c6 02 3b d0 72 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}