
rule TrojanDownloader_Win64_DCRat_G_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 0f 48 ff c1 03 c3 69 d8 ?? ?? ?? ?? 8b c3 c1 e8 ?? 33 d8 48 3b ca } //4
		$a_03_1 = {44 0f b6 c1 41 8d ?? ?? 0f b6 c8 41 8d ?? ?? 80 fa 19 41 0f 47 c8 41 ff c1 42 88 4c 14 ?? 45 8b d1 43 0f b7 04 4b 0f b6 c8 66 85 c0 } //2
		$a_03_2 = {0f b6 04 38 42 88 04 01 8b 84 24 ?? ?? ?? ?? ff c0 89 84 24 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=8
 
}