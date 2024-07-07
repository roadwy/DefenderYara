
rule VirTool_Win32_CeeInject_LY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 85 c0 89 45 e8 90 01 02 33 45 90 01 01 ff 45 90 01 01 8a 4d 90 01 01 33 c6 d3 c8 8b 4d 90 01 01 89 4d 90 01 01 89 02 83 c2 04 4f 90 00 } //1
		$a_03_1 = {8a 0a 0f b6 c9 8b f9 33 f8 83 e7 0f c1 e8 04 33 04 bd 90 01 04 c1 e9 04 8b f8 83 e7 0f 33 cf c1 e8 04 33 04 8d 90 01 04 4e 42 85 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}