
rule VirTool_Win32_VBInject_VL_bit{
	meta:
		description = "VirTool:Win32/VBInject.VL!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 78 04 ec 0c 56 8d 0f 85 90 01 04 e9 90 00 } //02 00 
		$a_03_1 = {83 f8 00 74 90 02 20 81 38 90 01 04 75 90 01 01 e9 90 01 03 00 90 00 } //01 00 
		$a_03_2 = {3b 7d 3c 0f 85 90 01 03 ff 90 00 } //01 00 
		$a_01_3 = {68 00 20 00 00 8f 45 3c } //00 00 
		$a_00_4 = {5d 04 00 00 } //2c 9c 
	condition:
		any of ($a_*)
 
}