
rule VirTool_Win32_CeeInject_BY{
	meta:
		description = "VirTool:Win32/CeeInject.BY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 48 3c 8b 55 fc 0f b7 04 0a 3d 50 45 00 00 90 0a 2f 00 83 e9 02 8b 95 90 01 01 fe ff ff 39 4a 3c 90 00 } //2
		$a_03_1 = {4c 64 72 50 72 6f 63 00 90 09 39 00 6c 64 72 2e 65 78 65 00 90 00 } //2
		$a_01_2 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8 } //1
		$a_01_3 = {68 dd 47 43 de 6a 01 e8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}