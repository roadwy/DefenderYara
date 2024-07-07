
rule VirTool_Win32_Injector_gen_AS{
	meta:
		description = "VirTool:Win32/Injector.gen!AS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 a1 90 01 04 8b 40 50 50 a1 90 01 04 8b 40 34 90 00 } //1
		$a_01_1 = {33 d2 8a 54 24 04 03 d7 33 d6 88 54 18 ff } //1
		$a_03_2 = {eb 0d 81 fe ff 00 00 00 75 05 be 01 00 00 00 90 02 08 89 ff 43 4f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}