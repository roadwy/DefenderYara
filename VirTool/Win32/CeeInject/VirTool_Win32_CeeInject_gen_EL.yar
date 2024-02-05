
rule VirTool_Win32_CeeInject_gen_EL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 50 50 8b 40 34 } //01 00 
		$a_03_1 = {8b 51 34 8b 0d 90 01 04 03 c2 90 09 08 00 90 02 05 8b 41 28 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}