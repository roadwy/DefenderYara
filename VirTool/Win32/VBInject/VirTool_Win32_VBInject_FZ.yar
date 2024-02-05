
rule VirTool_Win32_VBInject_FZ{
	meta:
		description = "VirTool:Win32/VBInject.FZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 e8 00 00 00 89 5d } //01 00 
		$a_01_1 = {b9 c3 00 00 00 ff d6 88 } //01 00 
		$a_01_2 = {8a 04 39 32 c2 83 c3 01 88 04 31 8b 44 24 18 70 0f } //00 00 
	condition:
		any of ($a_*)
 
}