
rule VirTool_Win32_Dogrobot_gen_L{
	meta:
		description = "VirTool:Win32/Dogrobot.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 b4 67 00 00 8b 44 24 08 c7 00 92 a5 00 00 eb 10 } //1
		$a_01_1 = {66 c7 45 ee 5c 00 66 c7 45 f0 61 00 66 c7 45 f2 74 00 66 c7 45 f4 61 00 66 c7 45 f6 70 00 66 c7 45 f8 69 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}