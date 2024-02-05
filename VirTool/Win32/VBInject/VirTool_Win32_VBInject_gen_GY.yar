
rule VirTool_Win32_VBInject_gen_GY{
	meta:
		description = "VirTool:Win32/VBInject.gen!GY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 52 8b 45 10 ff 30 e8 90 01 04 8a 1e 32 18 90 00 } //01 00 
		$a_03_1 = {8b 45 f8 2b 45 90 01 01 70 19 3d 98 3a 00 00 7d 07 66 83 4d fc ff eb 05 90 00 } //01 00 
		$a_03_2 = {7f 63 66 8b 45 90 01 01 66 05 01 00 0f 80 90 09 06 00 66 81 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}