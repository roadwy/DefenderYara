
rule VirTool_Win32_Injector_AI{
	meta:
		description = "VirTool:Win32/Injector.AI,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7d fc fd 03 01 00 73 42 } //1
		$a_01_1 = {68 d3 82 08 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}