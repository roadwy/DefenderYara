
rule VirTool_Win32_CeeInject_GX{
	meta:
		description = "VirTool:Win32/CeeInject.GX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 e9 66 81 e9 90 01 01 90 04 01 03 80 2d ff 0f 82 90 01 04 87 90 01 02 01 90 04 01 03 c0 2d ff 87 90 02 28 68 90 01 04 6a 00 68 00 00 10 00 2e ff 15 90 01 04 85 c0 0f 85 90 02 ff 68 90 1b 06 6a 00 68 00 00 10 00 2e ff 15 90 1b 07 83 f8 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}