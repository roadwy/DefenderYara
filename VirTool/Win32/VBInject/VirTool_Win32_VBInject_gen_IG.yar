
rule VirTool_Win32_VBInject_gen_IG{
	meta:
		description = "VirTool:Win32/VBInject.gen!IG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 8d 88 fd ff ff 8b 95 94 fd ff ff 03 ca } //01 00 
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //01 00 
		$a_01_2 = {c7 45 9c 58 59 59 59 } //01 00 
		$a_03_3 = {8b 85 20 ff ff ff 90 02 02 03 85 2c ff ff ff 90 02 06 89 85 20 fe ff ff 90 00 } //01 00 
		$a_01_4 = {6a 01 50 0f 80 8b 00 00 00 56 c7 45 a0 c3 00 00 00 e8 } //01 00 
	condition:
		any of ($a_*)
 
}