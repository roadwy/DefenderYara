
rule VirTool_Win32_Injector_HB{
	meta:
		description = "VirTool:Win32/Injector.HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 2f 0f d8 f0 [0-10] 46 [0-20] 31 f5 66 0f 73 d3 5c [0-10] 3b ac 24 10 02 00 00 } //1
		$a_03_1 = {31 32 66 0f fd d2 [0-20] 83 c2 04 0f d5 c1 [0-15] 39 5a fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}