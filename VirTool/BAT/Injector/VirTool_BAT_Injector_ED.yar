
rule VirTool_BAT_Injector_ED{
	meta:
		description = "VirTool:BAT/Injector.ED,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 1f 3c 28 } //1 ἂ⠼
		$a_03_1 = {20 00 30 00 00 1f 40 6f 90 01 01 00 00 06 90 00 } //1
		$a_03_2 = {20 f8 00 00 00 d6 11 90 01 01 1f 28 d8 d6 11 90 01 01 16 1f 28 28 90 00 } //1
		$a_01_3 = {2d 4d 61 6c 77 61 72 65 62 79 74 65 73 20 53 63 61 6e 6e 65 72 2d } //-300 -Malwarebytes Scanner-
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*-300) >=3
 
}