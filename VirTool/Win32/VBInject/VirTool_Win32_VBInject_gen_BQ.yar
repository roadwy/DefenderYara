
rule VirTool_Win32_VBInject_gen_BQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 84 fc 1c 00 94 84 fc 10 00 aa 71 9c fd 04 } //01 00 
		$a_03_1 = {f4 10 a9 e7 90 01 19 66 68 ff 18 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}