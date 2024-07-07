
rule VirTool_BAT_Injector_gen_J{
	meta:
		description = "VirTool:BAT/Injector.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 1f 5f 62 d2 20 00 01 00 00 5d 61 } //1
		$a_01_1 = {2c 3d 7e 01 00 00 04 16 9a 19 8d 01 00 00 01 0a 06 16 7e 01 00 00 04 17 9a a2 06 17 7e 01 00 00 04 18 9a a2 06 18 1f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}