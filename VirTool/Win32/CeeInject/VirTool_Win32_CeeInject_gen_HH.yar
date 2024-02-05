
rule VirTool_Win32_CeeInject_gen_HH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 8d 6c fe ff ff 03 8d 78 fe ff ff 89 8d 24 fc ff ff } //01 00 
		$a_01_1 = {8b 85 5c fe ff ff 03 85 68 fe ff ff 89 85 14 fc ff ff } //02 00 
		$a_01_2 = {b8 58 59 59 59 } //01 00 
	condition:
		any of ($a_*)
 
}