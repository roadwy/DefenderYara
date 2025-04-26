
rule VirTool_BAT_Injector_E{
	meta:
		description = "VirTool:BAT/Injector.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 2a 07 11 05 02 11 05 91 09 61 06 11 04 91 61 b4 9c 11 04 06 8e b7 17 da 33 05 16 13 04 2b 06 } //1
		$a_03_1 = {11 0e 11 0c 20 00 30 00 00 1f 40 6f ?? 00 00 06 13 0f 7e 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}