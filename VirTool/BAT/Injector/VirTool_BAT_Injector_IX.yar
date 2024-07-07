
rule VirTool_BAT_Injector_IX{
	meta:
		description = "VirTool:BAT/Injector.IX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c } //1
		$a_01_1 = {41 33 64 71 33 64 65 65 35 34 66 2e 72 65 73 6f 75 72 63 65 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}