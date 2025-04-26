
rule TrojanDownloader_Win32_Upatre_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 e7 58 [0-03] 3d 00 04 00 00 76 05 e9 } //5
		$a_03_1 = {be 20 00 00 00 ff 75 00 ff ?? ?? ?? ?? ?? 85 c0 75 0f 50 68 4c 04 00 00 ff ?? ?? ?? ?? ?? 4e 75 } //5
		$a_01_2 = {b1 04 ab 49 75 fc 57 b9 44 00 00 00 89 0f ab 49 75 fc } //5
		$a_80_3 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //  1
		$a_80_4 = {00 74 65 78 74 2f 2a 00 } //  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=17
 
}