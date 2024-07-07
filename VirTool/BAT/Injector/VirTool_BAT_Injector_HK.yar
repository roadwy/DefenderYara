
rule VirTool_BAT_Injector_HK{
	meta:
		description = "VirTool:BAT/Injector.HK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 61 28 } //1
		$a_01_1 = {08 20 9c 00 00 00 93 20 be 77 00 00 59 13 08 38 } //1
		$a_01_2 = {1f 1f 5f 1f 1f 5f 1f 1f 5f 1f 1f 5f 62 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}