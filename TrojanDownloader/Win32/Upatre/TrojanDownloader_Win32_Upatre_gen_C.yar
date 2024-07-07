
rule TrojanDownloader_Win32_Upatre_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_01_0 = {85 c0 74 e7 58 3d e8 03 00 00 72 05 e9 } //5
		$a_03_1 = {be 1e 00 00 00 ff 75 00 ff 90 01 05 85 c0 75 10 6a 01 68 e8 03 00 00 ff 90 01 05 4e 75 90 00 } //5
		$a_01_2 = {b9 04 00 00 00 ab e2 fd 57 b9 44 00 00 00 89 0f ab e2 fd } //5
		$a_80_3 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //  1
		$a_80_4 = {00 74 65 78 74 2f 2a 00 } //  1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=17
 
}