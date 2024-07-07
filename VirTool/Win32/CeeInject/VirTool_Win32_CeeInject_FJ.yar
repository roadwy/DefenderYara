
rule VirTool_Win32_CeeInject_FJ{
	meta:
		description = "VirTool:Win32/CeeInject.FJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc a3 90 01 04 a1 90 01 04 ff d0 8b 45 fc 8b 0d 90 01 04 8b 09 89 08 c7 45 f8 00 00 00 00 a1 90 01 04 8b 4d f8 3b c1 0f 85 1c 00 00 00 a1 90 01 04 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 01 e9 27 00 00 00 a1 90 01 04 8b 0d 90 01 04 33 c1 a3 90 01 04 8b 45 f8 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 01 08 8b 45 fc 8b 00 90 00 } //1
		$a_03_1 = {52 53 44 53 90 02 20 3a 5c 90 02 10 5c 90 02 10 5c 90 02 10 5c 90 02 20 2e 70 64 62 90 00 } //1
		$a_00_2 = {3d a7 72 5c 5e c7 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}