
rule VirTool_BAT_Injector_gen_K{
	meta:
		description = "VirTool:BAT/Injector.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 07 00 01 00 } //1
		$a_03_1 = {11 12 20 b0 00 00 00 d3 58 11 15 28 ?? ?? ?? ?? 11 0e 1f 28 d3 58 } //1
		$a_01_2 = {11 15 11 0e 1f 50 d3 58 4b 20 00 30 00 00 1f 40 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}