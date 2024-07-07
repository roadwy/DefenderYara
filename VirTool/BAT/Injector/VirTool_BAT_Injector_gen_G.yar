
rule VirTool_BAT_Injector_gen_G{
	meta:
		description = "VirTool:BAT/Injector.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7d 7d 3b 23 75 72 74 20 6e 72 75 74 23 72 3b 29 } //1 }};#urt nrut#r;)
		$a_01_1 = {4d 61 69 6e 00 52 65 76 65 72 73 65 72 00 73 00 } //1 慍湩刀癥牥敳rs
		$a_01_2 = {05 46 00 46 00 00 05 53 00 53 00 00 05 54 00 54 00 00 05 55 00 55 00 } //1
		$a_03_3 = {02 1f 23 1f 65 6f 90 01 01 00 00 0a 10 00 02 6f 90 01 01 00 00 0a 0a 06 28 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}