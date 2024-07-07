
rule VirTool_BAT_Injector_F{
	meta:
		description = "VirTool:BAT/Injector.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 91 07 61 08 06 91 61 b4 9c 06 08 8e b7 17 da 33 04 } //1
		$a_03_1 = {11 0e 11 0c 20 00 30 00 00 1f 40 6f 90 01 01 00 00 06 13 0f 7e 90 00 } //1
		$a_03_2 = {38 8b 00 00 00 1f 0a 8d 90 01 01 00 00 01 13 12 02 11 04 20 f8 00 00 00 d6 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}