
rule VirTool_Win32_Injector_gen_ES{
	meta:
		description = "VirTool:Win32/Injector.gen!ES,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 72 00 23 00 68 00 6e 00 00 00 } //01 00 
		$a_01_1 = {45 6e 74 65 72 20 61 20 6e 75 6d 62 65 72 20 74 6f 20 72 65 76 65 72 73 65 0a 00 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 20 00 6f 00 66 00 20 00 65 00 6e 00 74 00 65 00 72 00 65 00 64 00 } //01 00 
		$a_01_2 = {35 36 73 67 6a 73 66 67 6a 35 2e 70 64 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}