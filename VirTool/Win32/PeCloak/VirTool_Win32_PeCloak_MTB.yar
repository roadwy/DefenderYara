
rule VirTool_Win32_PeCloak_MTB{
	meta:
		description = "VirTool:Win32/PeCloak!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 f6 31 ff [0-30] 3d ?? ?? ?? ?? 75 [0-30] 3d ?? ?? ?? ?? 75 [0-30] 3d ?? ?? ?? ?? 75 [0-30] b8 [0-10] 80 30 [0-30] 80 28 [0-30] 80 00 [0-30] 40 3d ?? ?? ?? ?? 7e } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}