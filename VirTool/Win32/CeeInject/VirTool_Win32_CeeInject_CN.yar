
rule VirTool_Win32_CeeInject_CN{
	meta:
		description = "VirTool:Win32/CeeInject.CN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 44 24 30 44 00 00 00 c7 44 24 74 07 00 01 00 89 1d 90 01 04 66 81 3b 4d 5a 0f 85 90 00 } //01 00 
		$a_00_1 = {8a 54 9c 18 8a 1c 01 32 da 88 1c 01 41 3b cd 72 94 } //00 00 
	condition:
		any of ($a_*)
 
}