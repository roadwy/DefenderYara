
rule VirTool_Win32_CeeInject_GH{
	meta:
		description = "VirTool:Win32/CeeInject.GH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 4e 54 42 42 5f 42 42 4e ad 89 07 03 fa 49 75 f8 } //1
		$a_03_1 = {55 4e 4e 5f 33 c0 8b 06 89 07 47 47 47 47 83 c6 04 e2 f3 e8 90 01 02 00 00 e9 90 01 01 90 04 01 03 20 2d 40 00 00 90 00 } //1
		$a_03_2 = {3e 0f 18 00 50 16 33 c0 85 c0 17 74 90 02 28 05 00 10 00 00 8b 48 fc 32 cd 80 f9 10 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}