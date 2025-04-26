
rule VirTool_Win32_CeeInject_gen_CP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 38 7b 0f 85 6a 03 00 00 8b 45 f8 03 45 0c 40 80 38 61 0f 85 5a 03 00 00 8b 45 f8 03 45 0c 83 c0 02 80 38 64 0f 85 48 03 00 00 } //1
		$a_01_1 = {80 7e f9 7b 75 f0 80 7e fa 61 75 ea 80 7e fb 64 75 e4 80 7e fc 69 75 de 80 7e fd 66 75 d8 80 7e fe 7d 75 d2 } //1
		$a_01_2 = {80 3e 7b 75 f1 80 7e 01 61 75 eb 80 7e 02 64 75 e5 80 7e 03 69 75 df 80 7e 04 66 75 d9 80 7e 05 7d 75 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}