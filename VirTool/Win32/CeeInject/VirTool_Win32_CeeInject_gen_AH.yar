
rule VirTool_Win32_CeeInject_gen_AH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 20 00 00 8b 45 f0 8b 48 50 51 8b 55 f0 8b 42 34 50 ff 15 } //3
		$a_03_1 = {83 c0 01 89 45 ?? 8b 4d ?? 83 c1 28 89 4d ?? 8b 55 ?? 8b 02 33 c9 66 8b 48 06 39 4d } //2
		$a_01_2 = {49 4e 4a 45 43 54 5f 44 4c 4c 00 } //2
		$a_01_3 = {4d 41 49 4e 5f 44 4c 4c 00 } //1
		$a_01_4 = {4d 41 49 4e 5f 4b 45 59 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}