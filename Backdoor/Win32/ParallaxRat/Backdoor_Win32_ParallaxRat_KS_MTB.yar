
rule Backdoor_Win32_ParallaxRat_KS_MTB{
	meta:
		description = "Backdoor:Win32/ParallaxRat.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b c2 1a 8b d1 2b d0 8a 44 15 e0 30 81 ?? ?? ?? ?? 41 81 f9 00 b0 00 00 72 dc } //10
		$a_80_1 = {53 48 47 65 74 50 61 74 68 46 72 6f 6d 49 44 4c 69 73 74 41 } //SHGetPathFromIDListA  3
		$a_80_2 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 4c 6f 63 61 74 69 6f 6e } //SHGetSpecialFolderLocation  3
		$a_80_3 = {47 64 69 70 43 72 65 61 74 65 42 69 74 6d 61 70 46 72 6f 6d 48 42 49 54 4d 41 50 } //GdipCreateBitmapFromHBITMAP  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}