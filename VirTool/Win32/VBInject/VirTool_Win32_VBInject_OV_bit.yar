
rule VirTool_Win32_VBInject_OV_bit{
	meta:
		description = "VirTool:Win32/VBInject.OV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 90 01 03 00 90 02 30 8b 43 2c 90 02 30 31 c8 90 02 30 83 f8 00 75 90 00 } //01 00 
		$a_03_1 = {83 f8 00 75 90 02 30 6a 48 90 02 30 58 90 02 30 8b 14 03 90 02 30 31 f2 90 02 30 52 90 00 } //01 00 
		$a_03_2 = {64 ff 35 18 00 00 00 90 02 30 8b 90 01 01 30 90 02 30 02 90 01 01 02 90 02 30 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}