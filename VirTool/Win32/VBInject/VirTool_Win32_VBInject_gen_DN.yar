
rule VirTool_Win32_VBInject_gen_DN{
	meta:
		description = "VirTool:Win32/VBInject.gen!DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 05 00 00 00 c2 f5 02 00 00 00 aa fb 13 fc 0e } //01 00 
		$a_01_1 = {4a c2 f5 01 00 00 00 aa 6c 0c 00 4d f8 fe 08 40 } //01 00 
		$a_03_2 = {80 0c 00 fc 90 90 6c 78 ff 08 08 00 8a 90 03 01 01 3c 40 00 c2 08 08 00 8a 90 03 01 01 40 44 00 fc 90 90 fb 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}