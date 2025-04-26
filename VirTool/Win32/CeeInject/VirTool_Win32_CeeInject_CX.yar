
rule VirTool_Win32_CeeInject_CX{
	meta:
		description = "VirTool:Win32/CeeInject.CX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 51 3c 89 55 f0 8b 45 f0 81 38 50 45 00 00 74 0f 8b 4d c8 } //1
		$a_01_1 = {0f b7 48 06 39 4d ec 7d 3d 8b 55 ec 6b d2 28 8b 45 f8 } //1
		$a_01_2 = {8b 08 ff d1 8b 55 fc 83 7a 04 00 74 23 68 00 80 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}