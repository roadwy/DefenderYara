
rule TrojanDownloader_Win32_Small_KZ{
	meta:
		description = "TrojanDownloader:Win32/Small.KZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 33 36 30 68 61 6f 77 61 6e 2e 63 6e } //1 www.360haowan.cn
		$a_00_1 = {6d 61 74 63 36 } //1 matc6
		$a_03_2 = {83 c4 48 33 c9 80 ?? ?? ?? 00 8d ?? ?? ?? 75 03 c6 00 30 41 83 f9 0c 7c ec } //1
		$a_03_3 = {83 c4 1c 85 c0 75 21 68 88 13 00 00 ff 15 ?? ?? 40 00 8d 45 ?? 50 8d 85 ?? ?? ff ff 56 50 e8 ?? ?? ff ff 83 c4 0c eb db } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}