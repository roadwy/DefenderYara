
rule VirTool_BAT_Injector_gen_Q{
	meta:
		description = "VirTool:BAT/Injector.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 49 6e 6a 65 63 74 6f 72 20 4d 73 70 20 56 31 2e 90 01 01 2e 65 78 65 00 90 00 } //1
		$a_00_1 = {6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 20 00 4d 00 73 00 70 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}