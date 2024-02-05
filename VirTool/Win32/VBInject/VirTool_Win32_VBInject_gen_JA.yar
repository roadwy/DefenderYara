
rule VirTool_Win32_VBInject_gen_JA{
	meta:
		description = "VirTool:Win32/VBInject.gen!JA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 70 fe 6c 64 fe aa 30 9c fd } //01 00 
		$a_01_1 = {f5 58 59 59 59 } //01 00 
		$a_01_2 = {04 70 fe 4d c0 fc 03 40 fc 8f e0 fc 01 00 04 8c fe } //01 00 
		$a_01_3 = {f5 07 2e 01 00 } //01 00 
	condition:
		any of ($a_*)
 
}