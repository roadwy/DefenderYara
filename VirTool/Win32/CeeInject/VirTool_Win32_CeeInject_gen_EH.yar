
rule VirTool_Win32_CeeInject_gen_EH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 f8 00 00 00 8b 45 ec 50 8b c3 03 46 3c 50 ff 15 ?? ?? ?? ?? 8d 45 e0 50 8b 45 ec 8b 40 50 50 53 8b 45 e4 50 8b 45 d0 50 ff 15 ?? ?? ?? ?? 8d 45 e0 50 6a 04 8d 45 e4 50 8b 87 a4 00 00 00 83 c0 08 50 8b 45 d0 50 ff 15 ?? ?? ?? ?? 8b 45 ec 8b 40 28 03 45 e4 89 87 b0 00 00 00 57 8b 45 d4 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}