
rule VirTool_Win32_CeeInject_gen_JH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 11 52 e8 90 01 04 83 c4 04 8b 90 01 05 83 c0 01 89 90 01 05 8b 90 01 05 0f be 11 83 fa 21 74 02 eb 90 00 } //1
		$a_03_1 = {0f be 11 52 e8 90 01 04 83 c4 04 8b 90 01 02 83 c0 01 89 90 01 02 8b 90 01 02 0f be 11 83 fa 21 74 02 eb 90 00 } //1
		$a_03_2 = {75 73 61 00 90 03 0e 0b 48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21 00 54 6f 74 61 6c 3a 20 25 64 0a 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}