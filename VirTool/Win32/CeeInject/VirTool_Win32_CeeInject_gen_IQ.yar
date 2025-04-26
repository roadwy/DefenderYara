
rule VirTool_Win32_CeeInject_gen_IQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 51 3c 8b 45 ?? 6b c0 28 03 45 08 8d 8c 10 f8 00 00 00 } //1
		$a_03_1 = {03 41 28 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 ff 55 ?? a1 90 1b 02 50 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}