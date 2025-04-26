
rule VirTool_WinNT_Cutwail_gen_D{
	meta:
		description = "VirTool:WinNT/Cutwail.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 3d 28 0a 73 09 83 25 ?? ?? ?? ?? 00 eb 0c 75 0a c7 05 ?? ?? ?? ?? 64 01 00 00 } //2
		$a_03_1 = {ff 73 fc 8b 03 05 ?? ?? ?? ?? 50 8b 43 f8 03 45 dc 50 e8 ?? ?? ff ff 83 c3 28 ff 45 e0 0f b7 46 06 39 45 e0 7c da } //2
		$a_01_2 = {8b 46 28 03 45 } //1
		$a_01_3 = {68 4e 72 74 6b } //1 hNrtk
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}