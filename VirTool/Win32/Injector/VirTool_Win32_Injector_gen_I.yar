
rule VirTool_Win32_Injector_gen_I{
	meta:
		description = "VirTool:Win32/Injector.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c } //10
		$a_01_1 = {80 7c 24 1c 01 75 1c 8b 54 24 28 8b 43 1c 6a 40 68 00 30 00 00 52 50 56 ff 15 } //1
		$a_03_2 = {0f b7 40 06 85 c0 7e 2d 53 8b 5c 24 90 01 01 55 83 c3 08 8b e8 8b 0b 85 c9 74 14 33 d2 8b c1 f7 f6 85 d2 75 04 03 f9 eb 06 40 0f af c6 03 f8 83 c3 28 90 00 } //1
		$a_01_3 = {8b 47 34 6a 40 68 00 30 00 00 53 50 56 ff } //1
		$a_03_4 = {0f b7 55 06 40 83 c7 28 3b c2 89 44 24 90 01 01 7c 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=11
 
}