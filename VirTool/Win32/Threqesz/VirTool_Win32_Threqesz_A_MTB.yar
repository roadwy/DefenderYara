
rule VirTool_Win32_Threqesz_A_MTB{
	meta:
		description = "VirTool:Win32/Threqesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f0 85 f6 ?? ?? ?? ?? ?? ?? 8b 3d 18 20 40 00 ?? ?? ?? ?? ?? 56 ?? ?? a3 74 43 40 00 85 c0 [0-11] 56 ?? ?? 83 3d 74 43 40 00 00 a3 78 43 40 00 ?? ?? ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {6a 40 68 00 10 00 00 68 e4 00 00 00 b9 39 00 00 00 ?? ?? ?? ?? ?? ?? be c0 21 40 00 f3 a5 6a 00 ?? ?? ?? ?? ?? ?? 8b f8 89 bd ec f7 ff ff 85 ff } //1
		$a_03_2 = {8b e5 5d c3 57 [0-10] 83 c4 08 ?? ?? ?? ?? ?? ?? b9 39 00 00 00 f3 a5 ?? ?? ?? ?? ?? ?? 68 28 23 40 00 8b f0 ?? ?? 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}