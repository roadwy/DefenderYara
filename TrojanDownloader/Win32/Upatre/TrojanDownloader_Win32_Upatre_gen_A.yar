
rule TrojanDownloader_Win32_Upatre_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {fc ad ab 33 c0 66 ad ab e2 f7 } //2
		$a_03_1 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c } //2
		$a_80_2 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } //  1
		$a_80_3 = {00 74 65 78 74 2f 2a 00 } //  1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}