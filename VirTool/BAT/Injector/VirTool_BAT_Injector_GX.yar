
rule VirTool_BAT_Injector_GX{
	meta:
		description = "VirTool:BAT/Injector.GX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 70 69 63 20 2e 72 65 73 6f 75 72 63 65 73 00 } //1
		$a_00_1 = {63 00 6d 00 39 00 30 00 59 00 58 00 52 00 6c 00 4a 00 41 00 3d 00 3d 00 } //1 cm90YXRlJA==
		$a_01_2 = {1f 11 91 1f 4d 59 13 05 2b b4 03 04 61 1f 2b 59 06 61 45 01 00 00 00 05 00 00 00 19 13 05 2b 9e 1e 2b f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}