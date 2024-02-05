
rule VirTool_Win32_VBInject_WE{
	meta:
		description = "VirTool:Win32/VBInject.WE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 68 a1 6a 8b 4d 90 01 01 c7 81 90 01 02 00 00 3d d8 51 e8 90 00 } //01 00 
		$a_03_1 = {68 d0 37 10 8b 45 90 01 01 ba 90 01 04 c7 80 90 01 02 00 00 f2 51 e8 d5 90 00 } //01 00 
		$a_03_2 = {00 68 88 fe 8b 55 90 01 01 c7 82 90 01 02 00 00 b3 16 51 e8 90 00 } //01 00 
		$a_01_3 = {c1 cf 0d 03 8b 4d } //01 00 
	condition:
		any of ($a_*)
 
}