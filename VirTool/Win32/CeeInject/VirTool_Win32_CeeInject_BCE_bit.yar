
rule VirTool_Win32_CeeInject_BCE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BCE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 73 c6 45 f1 76 c6 45 f2 63 c6 45 f3 68 c6 45 f4 6f c6 45 f5 73 c6 45 f6 74 c6 45 f7 2e c6 45 f8 65 c6 45 f9 78 } //1
		$a_01_1 = {c6 45 ec 53 c6 45 ed 51 c6 45 ee 4c c6 45 ef 00 c6 45 c8 5a c6 45 c9 4b c6 45 ca 46 c6 45 cb 00 } //1
		$a_01_2 = {8b 45 08 03 45 e4 0f b6 08 8b 55 0c 03 55 e4 0f b6 02 33 c8 8b 55 08 03 55 e4 88 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}