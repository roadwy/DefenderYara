
rule VirTool_Win32_CeeInject_gen_HW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 50 ff 75 08 68 6e 1c 04 45 e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 59 ff d0 5e 5d c3 } //1
		$a_03_1 = {68 12 ba 0c c3 e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 59 a3 ?? ?? ?? ?? 5e ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0 } //1
		$a_01_2 = {0f b6 4d fc 83 45 f8 03 8b f1 c1 ee 02 8a 1c 3e 0f b6 75 fd 88 1a 83 e1 03 8b de c1 e1 04 c1 eb 04 0b d9 8a 0c 3b 88 4a 01 83 f8 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}