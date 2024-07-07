
rule VirTool_BAT_Injector_gen_CO{
	meta:
		description = "VirTool:BAT/Injector.gen!CO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 69 6f 6e 00 41 70 70 4c 61 75 6e 63 68 } //1
		$a_01_1 = {4d 65 6c 74 00 43 6f 70 69 61 7a 61 } //1 敍瑬䌀灯慩慺
		$a_01_2 = {58 6f 72 78 6f 72 78 6f 72 00 } //1 潘硲牯潸r
		$a_01_3 = {44 61 74 61 50 72 6f 74 65 63 74 6f 72 5c 43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //1 DataProtector\ClassLibrary1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}