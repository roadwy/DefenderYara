
rule VirTool_Win32_CeeInject_gen_EG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00 } //1 一啴浮灡楖睥晏敓瑣潩n
		$a_03_1 = {89 45 f8 8b 4d f4 51 8b 55 0c 52 ff 55 f8 6a 40 68 00 30 00 00 8b 45 fc 8b 48 50 51 8b 55 f4 52 8b 45 0c 50 ff 15 90 01 04 6a 00 8b 4d fc 8b 51 54 52 8b 45 08 50 8b 4d f4 51 8b 55 0c 52 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}