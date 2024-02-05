
rule VirTool_Win32_VBInject_AEL{
	meta:
		description = "VirTool:Win32/VBInject.AEL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {e5 e8 8b 45 90 01 01 66 c7 40 90 01 01 a4 03 90 09 04 00 66 c7 40 90 00 } //01 00 
		$a_03_1 = {ff 66 89 83 90 01 02 00 00 8b 5d cc 66 89 83 90 01 02 00 00 90 09 04 00 b8 90 90 90 90 ff 90 00 } //01 00 
		$a_03_2 = {00 00 31 37 8b 45 90 01 01 66 c7 80 90 01 02 00 00 83 c7 8b 45 90 01 01 66 c7 80 90 01 02 00 00 04 85 90 09 05 00 66 c7 80 90 00 } //01 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}