
rule VirTool_Win32_CeeInject_gen_EU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 11 81 e2 00 00 00 80 74 90 01 01 8b 45 90 01 01 8b 08 81 e1 ff ff 00 00 51 8b 55 90 01 01 52 ff 15 90 01 04 8b 4d 90 01 01 89 01 90 00 } //1
		$a_03_1 = {03 48 3c 89 4d 90 01 01 8b 55 90 01 01 8b 42 50 89 45 90 01 01 6a 00 8b 4d 90 01 01 51 8b 55 90 01 01 52 8b 45 08 50 8b 4d 90 01 01 51 ff 15 90 01 04 8b 55 90 01 01 8b 45 08 03 42 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}