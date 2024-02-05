
rule VirTool_Win32_VBInject_VI{
	meta:
		description = "VirTool:Win32/VBInject.VI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 e8 22 00 00 00 68 a4 4e } //01 00 
		$a_01_1 = {f6 0e ec 50 e8 4b 00 00 00 } //01 00 
		$a_01_2 = {f6 a1 6a 3d d8 51 e8 56 01 } //01 00 
		$a_01_3 = {f6 84 c0 74 07 c1 cf 0d 03 } //00 00 
	condition:
		any of ($a_*)
 
}