
rule VirTool_Win32_Refledelesz_A_MTB{
	meta:
		description = "VirTool:Win32/Refledelesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 84 24 58 01 00 00 00 00 00 00 50 ?? ?? ?? ?? ?? ?? ?? c7 84 24 74 01 00 00 ?? ?? ?? ?? 50 c7 84 24 7c 01 00 00 ?? ?? ?? ?? c7 84 24 80 01 00 00 ?? ?? ?? ?? 66 c7 84 24 84 01 00 00 ?? 00 c7 84 24 70 01 00 00 ?? ?? ?? ?? 66 c7 84 24 74 01 00 00 ?? 00 c7 44 24 14 [0-10] 50 } //1
		$a_03_1 = {8b f0 85 f6 [0-22] 50 6a 40 68 00 10 00 00 56 ?? ?? 85 c0 } //1
		$a_03_2 = {8b d8 89 9c 24 68 01 00 00 57 56 53 ?? ?? ?? ?? ?? 8b 73 3c 83 c4 0c 03 f3 89 74 24 0c 6a 40 68 00 30 00 00 ff 76 50 6a 00 ?? ?? ?? ?? ?? ?? ff 76 54 8b f8 53 57 } //1
		$a_03_3 = {c7 84 24 54 01 00 00 00 00 00 00 89 84 24 68 01 00 00 50 ?? ?? ?? ?? ?? ?? ?? 50 ff 74 9c 20 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 84 24 68 01 00 00 43 83 c0 06 89 84 24 68 01 00 00 83 fb 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}