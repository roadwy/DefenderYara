
rule VirTool_BAT_Injector_gen_A{
	meta:
		description = "VirTool:BAT/Injector.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 20 00 30 00 00 1a 28 ?? 00 00 06 } //1
		$a_03_1 = {00 00 04 20 00 30 00 00 1f 40 28 ?? 00 00 06 } //1
		$a_01_2 = {20 50 45 00 00 } //1
		$a_01_3 = {00 00 04 20 4d 5a 00 00 } //1
		$a_03_4 = {02 12 05 7c ?? 00 00 04 7b ?? 00 00 04 6e 28 ?? 00 00 0a 11 09 84 13 18 12 18 28 ?? 00 00 06 } //3
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //3 WriteProcessMemory
		$a_01_6 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //3 ZwUnmapViewOfSection
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=9
 
}