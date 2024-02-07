
rule VirTool_Win32_DelfInject_gen_CL{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 69 43 69 43 6f 64 65 72 00 } //01 00  楃楃潃敤r
		$a_01_1 = {63 72 79 70 74 6f 63 6f 64 65 00 } //01 00 
		$a_01_2 = {69 2b 2b 74 2b 65 2b 50 2b 72 2b 6f 2b 63 65 2b 2b 73 73 4d 2b 65 2b 6d 2b 6f 2b 72 79 } //00 00  i++t+e+P+r+o+ce++ssM+e+m+o+ry
	condition:
		any of ($a_*)
 
}