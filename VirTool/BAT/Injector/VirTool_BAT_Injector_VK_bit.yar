
rule VirTool_BAT_Injector_VK_bit{
	meta:
		description = "VirTool:BAT/Injector.VK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 20 19 28 bb 3d 58 9e 11 0f 17 58 13 0f 11 16 17 58 13 16 11 16 11 06 37 c1 } //1
		$a_03_1 = {1f 40 13 0e 7e ?? 00 00 04 11 05 28 ?? 00 00 0a 11 06 18 62 11 0e 12 0e 6f ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}