
rule VirTool_Win32_DelfInject_gen_CM{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 6a 00 ff 15 90 01 04 c7 05 90 01 04 02 00 01 00 90 00 } //01 00 
		$a_02_1 = {8b 40 54 50 a1 90 01 04 50 a1 90 01 04 50 a1 90 01 04 50 ff 15 90 01 04 a1 90 01 04 a3 90 01 04 81 05 90 01 04 f8 00 00 00 90 00 } //01 00 
		$a_01_2 = {63 72 79 70 74 6f 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}