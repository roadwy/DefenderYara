
rule VirTool_Win32_Injector_gen_F{
	meta:
		description = "VirTool:Win32/Injector.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {33 c9 45 66 8b 4f 06 83 c6 28 3b e9 72 ?? 8b 84 24 ?? ?? 00 00 8b 4c 24 ?? 6a 00 8d 54 24 ?? 6a 04 83 c0 08 52 50 51 ff } //10
		$a_03_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 6a 00 ff 15 } //5
		$a_03_2 = {8b 44 24 04 c1 e8 1d 8b 04 85 ?? ?? ?? ?? c3 } //5
		$a_03_3 = {6a 00 68 00 30 00 00 (8b 85 ?? ?? ff ff a1|?? ?? ?? ??) ff 70 50 (8b 85 ?? ?? ff ff a1|?? ?? ?? ??) ff 70 34 ff 90 03 04 06 35 ?? ?? ?? ?? b5 ?? ?? ff ff e8 } //5
		$a_03_4 = {0f b7 51 06 39 15 ?? ?? ?? ?? 73 90 09 13 00 a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? 8b 8d } //5
		$a_03_5 = {0f b7 40 06 39 05 ?? ?? ?? ?? 73 90 09 11 00 a1 90 1b 00 40 a3 90 1b 00 8b 85 } //5
		$a_03_6 = {0f b7 40 06 39 05 ?? ?? ?? ?? 7d 90 09 10 00 a1 90 1b 00 40 a3 90 1b 00 a1 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5+(#a_03_4  & 1)*5+(#a_03_5  & 1)*5+(#a_03_6  & 1)*5) >=10
 
}