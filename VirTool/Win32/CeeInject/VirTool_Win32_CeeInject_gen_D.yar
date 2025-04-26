
rule VirTool_Win32_CeeInject_gen_D{
	meta:
		description = "VirTool:Win32/CeeInject.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00 72 62 00 00 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1
		$a_01_1 = {00 8c 04 40 01 00 00 00 94 04 41 01 00 00 83 c0 02 83 f8 40 72 ea 56 57 b9 10 00 00 00 8d b4 24 48 01 00 00 8d 7c 24 28 f3 a5 66 81 7c 24 28 4d 5a } //1
		$a_01_2 = {45 78 70 6c } //1 Expl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}