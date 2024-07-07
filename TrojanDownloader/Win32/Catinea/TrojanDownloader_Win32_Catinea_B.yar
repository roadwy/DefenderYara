
rule TrojanDownloader_Win32_Catinea_B{
	meta:
		description = "TrojanDownloader:Win32/Catinea.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 08 b8 d4 07 00 00 66 a3 90 01 04 58 6a 90 01 01 66 a3 90 01 04 58 6a 02 90 00 } //2
		$a_03_1 = {d4 07 66 c7 05 90 01 04 08 00 66 c7 05 90 01 04 11 00 90 00 } //2
		$a_00_2 = {69 64 73 2f 25 73 69 64 65 2f 70 6f 73 2f 25 73 70 6f 65 2f 6a 6a 73 2f } //1 ids/%side/pos/%spoe/jjs/
		$a_00_3 = {79 78 3d 68 6f 73 74 26 77 6a 6d 3d 25 73 26 73 73 3d 25 73 } //1 yx=host&wjm=%s&ss=%s
		$a_00_4 = {2d 69 6e 75 6c 20 2d 79 20 2d 65 70 32 20 2d 6f 2b } //1 -inul -y -ep2 -o+
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}