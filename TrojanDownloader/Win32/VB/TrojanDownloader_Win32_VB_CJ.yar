
rule TrojanDownloader_Win32_VB_CJ{
	meta:
		description = "TrojanDownloader:Win32/VB.CJ,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3c 00 07 00 00 "
		
	strings :
		$a_00_0 = {56 42 35 21 36 26 76 62 36 63 68 73 2e 64 6c 6c } //10 VB5!6&vb6chs.dll
		$a_02_1 = {68 74 74 70 3a 2f 2f [0-20] 2f [0-08] 2e 65 78 65 } //10
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_02_3 = {2e 00 65 00 78 00 65 00 90 09 10 00 [0-10] 63 00 3a 00 5c 00 } //10
		$a_02_4 = {2e 00 62 00 61 00 74 00 90 09 10 00 [0-10] 63 00 3a 00 5c 00 } //10
		$a_00_5 = {40 00 65 00 63 00 68 00 6f 00 20 00 6f 00 66 00 66 00 } //10 @echo off
		$a_00_6 = {6d 75 74 6f 75 78 69 61 7a 61 69 } //1 mutouxiazai
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*1) >=60
 
}