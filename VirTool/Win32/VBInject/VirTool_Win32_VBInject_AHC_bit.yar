
rule VirTool_Win32_VBInject_AHC_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 70 ca 10 00 [0-20] 05 e6 35 31 00 [0-20] 39 41 04 [0-20] 68 cd 7b 34 00 [0-20] 58 [0-20] 05 80 84 1e 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHC_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 e0 [0-20] 41 [0-20] 0f 6e d9 [0-20] 0f fe e3 [0-20] 8b 40 2c [0-20] 0f 6e e8 [0-20] 0f ef ec [0-20] 0f 7e eb [0-20] 83 fb 00 75 } //1
		$a_03_1 = {83 fb 00 75 [0-40] ff 34 1c [0-20] 58 [0-20] e8 ?? ?? ?? 00 [0-20] 89 04 1c [0-20] 83 fb 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}