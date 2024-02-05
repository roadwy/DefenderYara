
rule VirTool_Win32_DelfInject_U{
	meta:
		description = "VirTool:Win32/DelfInject.U,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 42 46 49 53 48 00 10 da 42 54 50 00 } //02 00 
		$a_01_1 = {74 3e bf 01 00 00 00 0f b6 03 3c 2d 75 06 83 cf ff 43 } //02 00 
		$a_01_2 = {83 c0 78 8b 10 89 55 e0 03 50 04 89 55 dc 8b 45 e0 03 c3 8b 48 10 } //01 00 
	condition:
		any of ($a_*)
 
}