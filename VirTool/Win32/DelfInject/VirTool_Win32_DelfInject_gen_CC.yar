
rule VirTool_Win32_DelfInject_gen_CC{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 04 8d 45 90 01 01 50 8b 87 a4 00 00 00 83 c0 08 50 8b 45 90 01 01 50 ff 15 90 01 04 8b 45 90 01 01 03 43 28 89 87 b0 00 00 00 57 8b 45 90 01 01 50 ff 15 90 01 04 8b 45 90 01 01 50 ff 15 90 00 } //01 00 
		$a_03_1 = {50 33 c9 ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 53 ff 16 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}