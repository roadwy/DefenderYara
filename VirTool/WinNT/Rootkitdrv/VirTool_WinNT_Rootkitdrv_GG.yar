
rule VirTool_WinNT_Rootkitdrv_GG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 8b 08 40 40 66 85 c9 75 f6 2b c2 d1 f8 33 c9 85 c0 7e 09 66 ff 0c 4e 41 3b c8 7c } //3
		$a_01_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 6a 20 } //2
		$a_03_2 = {01 45 f8 83 c7 16 83 c6 04 4b 75 ?? fb 0f 20 c0 0d 00 00 01 00 } //2
		$a_03_3 = {01 00 68 c6 81 ?? ?? 01 00 c3 83 c1 16 81 f9 90 09 0d 00 ab ab 83 } //3
		$a_01_4 = {44 00 77 00 53 00 68 00 69 00 65 00 6c 00 64 00 00 00 } //1
		$a_01_5 = {50 00 41 00 56 00 44 00 52 00 56 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}