
rule VirTool_Win32_DelfInject_gen_DM{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 84 85 f8 fb ff ff 30 04 32 ff 45 f8 } //01 00 
		$a_01_1 = {c7 45 e4 4b 56 4d 4b c7 45 e8 56 4d 4b 56 } //01 00 
		$a_01_2 = {6a 30 59 64 8b 01 80 78 02 00 0f 85 07 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}