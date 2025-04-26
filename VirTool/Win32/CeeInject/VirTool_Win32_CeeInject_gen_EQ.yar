
rule VirTool_Win32_CeeInject_gen_EQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d3 6a 00 ff 76 54 89 45 f0 57 ff 75 08 ff 75 0c ff d0 83 65 fc 00 33 c0 66 3b 46 06 73 } //1
		$a_01_1 = {8d 84 38 f8 00 00 00 ff 70 10 8b 48 14 8b 40 0c 03 45 08 03 cf 51 50 ff 75 0c ff 55 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}