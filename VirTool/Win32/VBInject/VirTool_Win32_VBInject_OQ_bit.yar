
rule VirTool_Win32_VBInject_OQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.OQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 [0-20] 0f 6e [0-20] 0f fe [0-20] 8b 40 2c [0-20] 0f 6e [0-20] 0f ef } //1
		$a_03_1 = {83 fb 00 75 [0-20] 0f 7e [0-40] ff 34 1c [0-20] 58 [0-20] e8 ?? ?? ?? 00 [0-20] 89 04 1c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}