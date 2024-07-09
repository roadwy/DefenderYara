
rule VirTool_Win32_CeeInject_gen_FC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 47 3c 03 c3 50 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 8b 45 ?? 8b 40 50 50 53 8b 45 ?? 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 6a 04 8d 45 ?? 50 8b 45 f0 8b 80 a4 00 00 00 83 c0 08 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b c6 2b c6 03 45 ?? 8b 55 e8 03 42 28 8b 55 f0 89 82 b0 00 00 00 8b 45 f0 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 89 45 f4 68 00 80 00 00 6a 00 8b 45 ec 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}