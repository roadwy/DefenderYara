
rule VirTool_Win32_DelfInject_gen_DA{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c e8 0f 84 90 01 02 00 00 e8 90 01 02 ff ff 3c ff 0f 84 90 00 } //01 00 
		$a_01_1 = {30 04 3a 47 ff 4d e8 75 a5 8b 45 fc e8 } //02 00 
		$a_03_2 = {8b 40 3c 03 45 fc 89 45 90 01 01 8b 45 90 01 01 8b 58 50 6a 04 68 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}