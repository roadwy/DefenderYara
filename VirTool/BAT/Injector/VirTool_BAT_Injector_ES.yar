
rule VirTool_BAT_Injector_ES{
	meta:
		description = "VirTool:BAT/Injector.ES,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 20 00 01 00 00 5a 13 05 11 06 17 58 13 06 11 06 11 04 fe 04 13 08 11 08 2d e4 09 11 05 07 11 04 91 5a 58 0d 00 11 04 17 58 13 04 11 04 1a fe 04 13 08 11 08 } //1
		$a_01_1 = {02 7b 03 00 00 04 06 02 7b 03 00 00 04 06 91 02 7b 04 00 00 04 07 91 61 d2 9c 07 17 58 0b 07 02 7b 04 00 00 04 8e 69 fe 04 0c 08 2d d3 06 17 58 0a 06 02 7b 03 00 00 04 8e 69 fe 04 0c 08 2d bc 2a } //1
		$a_03_2 = {02 22 00 00 c0 40 22 00 00 50 41 73 ?? 00 00 0a 28 ?? 00 00 0a 00 02 17 28 ?? 00 00 0a 00 02 20 e9 01 00 00 20 c7 00 00 00 73 ?? 00 00 0a 28 ?? 00 00 0a 00 02 72 01 00 00 70 28 ?? 00 00 0a 00 02 72 01 00 00 70 6f ?? 00 00 0a 00 02 02 fe 06 07 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}