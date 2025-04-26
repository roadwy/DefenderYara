
rule VirTool_WinNT_Sanpec_gen_A{
	meta:
		description = "VirTool:WinNT/Sanpec.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4b 60 8b 41 0c 2d 0c e0 22 00 56 57 c7 45 f8 04 00 00 c0 0f 84 ?? 01 00 00 6a 04 5a 2b c2 } //2
		$a_03_1 = {80 71 8b 40 38 68 00 20 00 00 90 09 05 00 c7 45 } //2
		$a_03_2 = {8b 41 04 8d 14 24 cd 2e 83 c4 14 ff 75 ?? ff 15 } //1
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 72 00 6f 00 63 00 50 00 61 00 6e 00 61 00 6d 00 61 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}