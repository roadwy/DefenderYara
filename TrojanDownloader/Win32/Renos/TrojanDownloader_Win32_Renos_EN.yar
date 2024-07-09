
rule TrojanDownloader_Win32_Renos_EN{
	meta:
		description = "TrojanDownloader:Win32/Renos.EN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b f0 2b f2 8d 9b 00 00 00 00 8a 0a 80 f1 ?? 88 0c 16 74 08 8a 4a 01 42 84 c9 75 ee } //3
		$a_01_1 = {75 1a 83 c3 07 83 ee 07 83 c7 07 83 fb 46 72 c2 } //2
		$a_01_2 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //2
		$a_00_3 = {c7 46 0c 76 54 32 10 } //1
		$a_03_4 = {c7 06 01 23 45 67 0f bf ?? ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=7
 
}