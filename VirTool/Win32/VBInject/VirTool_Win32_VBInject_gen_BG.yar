
rule VirTool_Win32_VBInject_gen_BG{
	meta:
		description = "VirTool:Win32/VBInject.gen!BG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {fe ff ff 50 45 00 00 0f 85 90 09 03 00 81 bd } //1
		$a_03_1 = {83 c4 54 03 85 ?? fd ff ff ba ?? ?? ?? ?? 0f 80 } //1
		$a_03_2 = {66 8b d7 66 c1 fa 0f 8b da 33 1d ?? ?? ?? ?? 33 55 ?? 66 3b da 7f 39 0f bf d9 3b de 72 05 } //2
		$a_03_3 = {7f 28 66 b9 cc 00 e8 ?? ?? ff ff 57 ff 35 ?? ?? ?? ?? 8a d8 e8 ?? ?? ff ff 88 18 6a 01 58 03 c7 0f 80 ?? ?? ?? ?? 8b f8 eb d3 66 b9 58 00 e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}