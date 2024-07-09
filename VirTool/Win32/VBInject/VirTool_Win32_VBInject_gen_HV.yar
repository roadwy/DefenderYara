
rule VirTool_Win32_VBInject_gen_HV{
	meta:
		description = "VirTool:Win32/VBInject.gen!HV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 RtlMoveMemory
		$a_03_1 = {8d 4d ec e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d ec e8 ?? ?? ?? ?? 8d 45 ec 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}