
rule VirTool_Win32_CeeInject_gen_BF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!BF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c6 28 43 66 8b 41 02 3b d8 7e c6 8b 44 24 90 01 01 68 90 01 04 8b 48 10 03 cf 90 00 } //01 00 
		$a_03_1 = {66 81 7d 00 4d 5a 0f 85 90 01 04 8b 75 3c 03 f5 81 3e 50 45 00 00 74 0c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}