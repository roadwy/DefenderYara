
rule VirTool_Win32_VBInject_gen_IP{
	meta:
		description = "VirTool:Win32/VBInject.gen!IP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 90 07 00 01 00 } //01 00 
		$a_01_1 = {68 c2 8c 10 c5 } //01 00 
		$a_00_2 = {31 00 37 00 36 00 35 00 31 00 33 00 39 00 33 00 34 00 39 00 } //01 00 
	condition:
		any of ($a_*)
 
}