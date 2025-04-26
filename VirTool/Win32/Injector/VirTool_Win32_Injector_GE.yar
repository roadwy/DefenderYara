
rule VirTool_Win32_Injector_GE{
	meta:
		description = "VirTool:Win32/Injector.GE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f6 90 c6 45 f7 8b c6 45 f8 ff c6 45 f9 55 6a 06 8d 45 f4 } //1
		$a_01_1 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb } //1
		$a_01_2 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } //1
		$a_01_3 = {c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00 8d 45 dc 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}