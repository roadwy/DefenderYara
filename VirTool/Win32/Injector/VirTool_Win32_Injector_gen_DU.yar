
rule VirTool_Win32_Injector_gen_DU{
	meta:
		description = "VirTool:Win32/Injector.gen!DU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 79 20 46 72 61 6e 6b 69 6e 20 42 69 74 63 68 00 } //1
		$a_01_1 = {69 27 6d 20 6e 6f 74 20 61 20 6d 61 67 69 63 20 62 75 74 20 74 68 65 20 6e 75 6d 62 65 72 20 79 6f 75 20 63 68 6f 69 63 65 20 77 61 73 3a 0a 0a 20 25 69 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}