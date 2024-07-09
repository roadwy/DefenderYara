
rule VirTool_Win32_VBInject_OT_bit{
	meta:
		description = "VirTool:Win32/VBInject.OT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 35 18 00 00 00 [0-30] 8b ?? 30 [0-30] 02 ?? 02 [0-30] ff } //1
		$a_03_1 = {83 f9 00 0f 85 [0-40] 0f 6e [0-40] 8b ?? 2c [0-30] 0f 6e [0-30] 0f ef [0-30] 0f 7e } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=2
 
}