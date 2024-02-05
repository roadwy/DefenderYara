
rule VirTool_Win32_VBInject_gen_FC{
	meta:
		description = "VirTool:Win32/VBInject.gen!FC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f3 b8 00 fc 0d } //01 00 
		$a_01_1 = {f3 c3 00 fc 0d } //01 00 
		$a_01_2 = {f5 09 96 2a 3f } //01 00 
		$a_01_3 = {f5 95 e3 35 69 } //00 00 
	condition:
		any of ($a_*)
 
}