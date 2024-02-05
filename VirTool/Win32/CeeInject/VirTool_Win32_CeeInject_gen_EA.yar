
rule VirTool_Win32_CeeInject_gen_EA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EA,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 02 6a 01 8b 4d d4 51 ff 55 fc } //01 00 
		$a_01_1 = {52 6a 00 6a 00 6a 24 6a 00 6a 00 6a 00 8b 45 0c 50 6a 00 ff 55 a0 83 7d 0c 00 74 1d } //00 00 
	condition:
		any of ($a_*)
 
}