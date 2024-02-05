
rule VirTool_Win32_DelfInject_gen_CU{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 52 3c 03 d0 83 c2 04 83 c2 14 8b 42 38 89 45 90 01 01 33 f6 6a 40 68 00 30 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}