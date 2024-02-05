
rule VirTool_Win32_DelfInject_gen_CD{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 03 8d 04 80 03 05 90 01 04 8b 15 90 01 04 03 d0 8b c6 b9 28 00 00 00 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {83 c0 02 89 45 f0 6a 04 68 00 30 00 00 ff 75 fc ff 75 f8 ff 75 f4 8b 45 f0 83 e8 02 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}