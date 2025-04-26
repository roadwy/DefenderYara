
rule VirTool_Win32_CeeInject_LM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 01 8a ?? ?? ?? ?? ?? ?? 32 da 88 1c 01 } //1
		$a_03_1 = {8a 5d 00 8b ?? ?? ?? 8a ?? ?? ?? 32 d8 46 85 d2 88 5d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}