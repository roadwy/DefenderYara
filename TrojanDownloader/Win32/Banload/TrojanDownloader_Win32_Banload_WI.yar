
rule TrojanDownloader_Win32_Banload_WI{
	meta:
		description = "TrojanDownloader:Win32/Banload.WI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 90 01 03 ff 8b 55 ec 8d 45 f4 e8 90 01 03 ff 46 4b 75 d6 90 00 } //2
		$a_03_1 = {77 32 6a 00 68 80 00 00 00 6a 03 6a 00 8b c3 25 f0 00 00 00 c1 e8 04 8b 04 85 4c 71 46 00 50 8b 04 b5 40 71 46 00 50 8b c7 e8 90 01 03 ff 50 e8 90 01 03 ff 90 00 } //1
		$a_01_2 = {59 45 45 41 0b 1e 1e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}