
rule VirTool_Win32_CeeInject_LW{
	meta:
		description = "VirTool:Win32/CeeInject.LW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 02 33 85 90 01 02 ff ff 8b 4d 90 01 01 89 01 8b e5 5d c3 90 00 } //01 00 
		$a_01_1 = {55 8b ec 8b 45 08 8b 08 03 4d 0c 8b 55 08 89 0a 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}