
rule TrojanDownloader_Win32_Swizzor_gen_G{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 fb 5a 7e d9 39 7d fc 75 07 c7 45 fc 6e e1 00 00 81 75 fc 1c f5 00 00 } //1
		$a_03_1 = {0f b6 39 8b d6 81 e2 ff 00 00 00 33 d7 c1 ee 08 33 34 95 ?? ?? ?? ?? 83 e8 01 83 c1 01 85 c0 75 df } //1
		$a_03_2 = {f7 79 04 8b 01 b9 01 00 00 00 2b 4e fc 32 1c 02 8b 56 f4 8b 46 f8 8d 6a 01 2b c5 0b c1 89 54 24 ?? 7d 12 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}