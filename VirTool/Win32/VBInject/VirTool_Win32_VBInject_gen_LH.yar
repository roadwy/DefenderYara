
rule VirTool_Win32_VBInject_gen_LH{
	meta:
		description = "VirTool:Win32/VBInject.gen!LH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 b9 24 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 c7 45 ?? ?? 00 00 00 81 7d d4 ?? ?? 00 00 73 09 83 a5 ?? ?? ?? ?? 00 eb 0b e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 66 b9 28 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 c7 45 ?? ?? 00 00 00 81 7d d4 ?? ?? 00 00 73 09 83 a5 ?? ?? ?? ?? 00 eb 0b e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 66 b9 89 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}