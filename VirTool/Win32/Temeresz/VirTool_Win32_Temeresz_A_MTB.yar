
rule VirTool_Win32_Temeresz_A_MTB{
	meta:
		description = "VirTool:Win32/Temeresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 53 56 57 68 3c 32 40 00 e8 ?? ?? ?? ?? 68 5c 32 40 00 e8 ?? ?? ?? ?? 83 c4 08 6a 00 6a 00 68 10 11 40 00 6a 0d ff 15 } //1
		$a_03_1 = {81 3d 80 43 40 00 a2 00 00 00 57 ?? ?? 81 fe a5 00 00 00 ?? ?? 68 84 31 40 00 e8 ?? ?? ?? ?? 83 c4 04 c7 45 0c 00 00 00 00 6a 10 ff 15 ?? ?? ?? ?? 0f b7 f8 8d ?? ?? c1 ef 0f 83 e7 } //1
		$a_03_2 = {85 ff 74 2d ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d ?? ?? 51 50 ff 15 ?? ?? ?? ?? 33 c0 39 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}