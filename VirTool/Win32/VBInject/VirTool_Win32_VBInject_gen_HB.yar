
rule VirTool_Win32_VBInject_gen_HB{
	meta:
		description = "VirTool:Win32/VBInject.gen!HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 1c 8b 8d 90 01 02 ff ff 03 41 10 8b 4d 08 89 81 48 02 00 00 90 00 } //01 00 
		$a_01_1 = {89 81 98 01 00 00 } //01 00 
		$a_01_2 = {8b 80 3c 02 00 00 83 c0 08 } //01 00 
	condition:
		any of ($a_*)
 
}