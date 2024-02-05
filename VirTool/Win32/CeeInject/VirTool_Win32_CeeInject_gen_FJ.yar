
rule VirTool_Win32_CeeInject_gen_FJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 56 8b 74 24 0c 33 c9 85 f6 74 0c 8a 54 24 10 30 14 01 41 3b ce 72 f8 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad } //00 00 
	condition:
		any of ($a_*)
 
}