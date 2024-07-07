
rule VirTool_Win32_VBInject_AHC_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 70 ca 10 00 90 02 20 05 e6 35 31 00 90 02 20 39 41 04 90 02 20 68 cd 7b 34 00 90 02 20 58 90 02 20 05 80 84 1e 00 90 02 20 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHC_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 e0 90 02 20 41 90 02 20 0f 6e d9 90 02 20 0f fe e3 90 02 20 8b 40 2c 90 02 20 0f 6e e8 90 02 20 0f ef ec 90 02 20 0f 7e eb 90 02 20 83 fb 00 75 90 00 } //1
		$a_03_1 = {83 fb 00 75 90 02 40 ff 34 1c 90 02 20 58 90 02 20 e8 90 01 03 00 90 02 20 89 04 1c 90 02 20 83 fb 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}