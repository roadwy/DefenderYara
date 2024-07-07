
rule VirTool_Win32_CeeInject_gen_KJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 b8 0b 00 00 6a 00 ff 15 90 01 04 b9 ee 02 00 00 be 90 01 04 8b f8 f3 a5 ff d0 90 00 } //1
		$a_03_1 = {8a 54 08 0a 88 91 90 01 04 41 81 f9 b8 0b 00 00 72 ed 8a 45 f9 a2 90 01 04 e8 90 01 04 b8 90 01 04 ff d0 90 00 } //1
		$a_03_2 = {34 08 00 00 7d 90 01 01 e8 90 01 01 ff ff ff 90 09 06 00 81 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}