
rule VirTool_Win32_Injector_T{
	meta:
		description = "VirTool:Win32/Injector.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0c 60 8b 8d 90 01 01 ff ff ff 03 c8 89 8d 90 01 01 ff ff ff 8b 85 90 01 01 ff ff ff d1 e0 89 85 90 01 01 ff ff ff eb 90 00 } //02 00 
		$a_01_1 = {66 9c 72 0a 74 03 75 01 e8 e8 02 00 00 00 72 f4 83 c4 04 66 9d 74 03 75 01 } //01 00 
		$a_03_2 = {8b 40 3c 8b 8d 90 01 02 ff ff 6b c9 28 03 4d 0c 8d 84 01 f8 00 00 00 90 00 } //01 00 
		$a_01_3 = {e8 e8 72 f4 e8 83 c4 04 66 9d eb 01 e8 } //00 00 
	condition:
		any of ($a_*)
 
}