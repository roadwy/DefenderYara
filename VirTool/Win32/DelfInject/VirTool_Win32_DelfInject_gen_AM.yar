
rule VirTool_Win32_DelfInject_gen_AM{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 43 34 50 8b 45 90 01 01 50 ff 90 00 } //01 00 
		$a_03_1 = {83 f8 02 74 05 83 f8 01 75 04 8a 0a 02 d9 40 42 3d 90 01 02 00 00 75 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}