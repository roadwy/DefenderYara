
rule VirTool_BAT_Injector_gen_F{
	meta:
		description = "VirTool:BAT/Injector.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-04] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //1
		$a_03_1 = {03 00 70 6f 06 00 00 06 06 72 ?? ?? 00 70 6f 06 00 00 06 28 05 00 00 2b 13 05 02 06 } //1
		$a_01_2 = {49 20 4d 5a 00 00 2e 02 16 2a 11 10 1f 3c d3 58 4a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}