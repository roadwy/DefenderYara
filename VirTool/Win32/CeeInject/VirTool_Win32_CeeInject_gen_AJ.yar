
rule VirTool_Win32_CeeInject_gen_AJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca } //01 00 
		$a_03_1 = {8b 51 34 8b 85 90 01 02 ff ff 03 50 28 89 95 90 01 02 ff ff eb 90 00 } //01 00 
		$a_01_2 = {b8 68 58 4d 56 } //01 00 
		$a_01_3 = {81 bd 50 fc ff ff 81 57 03 00 } //01 00 
	condition:
		any of ($a_*)
 
}