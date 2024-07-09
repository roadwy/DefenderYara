
rule VirTool_Win32_Tamfer_A_MTB{
	meta:
		description = "VirTool:Win32/Tamfer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 b8 00 00 00 00 00 00 00 00 ff e0 } //1
		$a_03_1 = {41 56 48 83 ec 40 4c 8b f1 49 8b f1 48 8d ?? ?? ?? ?? ?? 41 8b e8 48 8b fa 33 db ff 15 ?? ?? ?? ?? 48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4c 8b d0 48 85 c0 } //1
		$a_03_2 = {4c 8b d1 b8 ?? 00 00 00 0f 05 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}