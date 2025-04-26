
rule VirTool_Win32_VBInject_AGI_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e d1 0f 6f c2 0f ef c1 0f fe ca 0f 7e c0 d9 d0 3d ?? ?? ?? ?? 75 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}