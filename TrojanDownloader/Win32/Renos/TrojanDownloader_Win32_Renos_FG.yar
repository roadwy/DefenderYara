
rule TrojanDownloader_Win32_Renos_FG{
	meta:
		description = "TrojanDownloader:Win32/Renos.FG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0 } //1
		$a_01_1 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0 0f b6 c0 } //1
		$a_01_2 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //1
		$a_02_3 = {6a 0c 8d 45 d8 50 68 00 14 2d 00 ff 75 e8 ff 15 90 01 02 40 00 90 00 } //2
		$a_03_4 = {83 c7 07 83 c6 07 83 ff 46 90 03 01 02 72 0f 82 90 09 12 00 90 02 03 83 c4 18 85 c0 75 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*2+(#a_03_4  & 1)*2) >=6
 
}