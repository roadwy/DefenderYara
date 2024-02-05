
rule VirTool_Win32_CeeInject_gen_S{
	meta:
		description = "VirTool:Win32/CeeInject.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 06 8b 85 90 01 01 fe ff ff 8b 8d 90 01 01 fe ff ff 03 c8 90 00 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 } //02 00 
		$a_01_2 = {8a 84 95 f8 fb ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72 } //00 00 
	condition:
		any of ($a_*)
 
}