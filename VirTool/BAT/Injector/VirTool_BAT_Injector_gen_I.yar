
rule VirTool_BAT_Injector_gen_I{
	meta:
		description = "VirTool:BAT/Injector.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 5c 08 09 58 20 f8 00 00 00 d3 58 1f 28 d3 11 90 01 01 5a 58 13 90 00 } //1
		$a_01_1 = {1f 3c 58 e0 4b 58 1f 78 58 e0 4b 58 0a 16 0b 2b 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}