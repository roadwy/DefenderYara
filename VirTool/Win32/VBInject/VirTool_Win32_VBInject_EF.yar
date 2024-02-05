
rule VirTool_Win32_VBInject_EF{
	meta:
		description = "VirTool:Win32/VBInject.EF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {e7 f5 4d 5a 00 00 c7 c3 1c } //01 00 
		$a_01_1 = {f4 05 a9 c1 fb 12 fc 0d } //01 00 
		$a_00_2 = {34 00 44 00 35 00 41 00 39 00 30 00 30 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}