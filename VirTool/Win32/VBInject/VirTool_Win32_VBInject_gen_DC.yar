
rule VirTool_Win32_VBInject_gen_DC{
	meta:
		description = "VirTool:Win32/VBInject.gen!DC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 8d ac fe ff ff 8b 95 b8 fe ff ff 90 02 16 89 8d 64 fe ff ff 90 00 } //02 00 
		$a_03_1 = {03 ca 8b 55 90 01 01 0f 80 90 01 04 89 8a b0 00 00 00 90 00 } //01 00 
		$a_01_2 = {c7 00 07 00 01 00 } //01 00 
		$a_01_3 = {b9 59 00 00 00 ff 15 } //01 00 
		$a_01_4 = {b9 c3 00 00 00 ff 15 } //01 00 
	condition:
		any of ($a_*)
 
}