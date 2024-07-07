
rule VirTool_BAT_Injector_HW{
	meta:
		description = "VirTool:BAT/Injector.HW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c } //1
		$a_01_1 = {20 b3 2d 00 00 0b 07 20 b3 2d 00 00 33 06 06 28 } //1
		$a_01_2 = {53 65 63 6f 6e 64 53 65 6d 65 73 74 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}