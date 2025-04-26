
rule TrojanDownloader_Win32_Monkif_K{
	meta:
		description = "TrojanDownloader:Win32/Monkif.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4 } //2
		$a_01_1 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed } //1
		$a_01_2 = {58 6a 0f 50 cb } //1
		$a_03_3 = {8a c8 80 e9 ?? 30 88 ?? ?? ?? ?? 40 3d 18 25 00 00 7c ed } //2
		$a_01_4 = {ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd } //2
		$a_01_5 = {a9 00 00 02 00 59 75 e9 a8 20 75 e5 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=4
 
}