
rule VirTool_Win32_CeeInject_gen_EO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 5d 10 56 57 8d 7b 05 8b f1 57 e8 ?? ?? ?? ?? 59 89 06 8d 4d fc 51 6a 40 57 50 ff 15 ?? ?? ?? ?? ff 75 08 ff 75 0c ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 53 50 ff 36 89 45 10 } //1
		$a_03_1 = {8b 40 3c 03 45 fc 8d 84 30 f8 00 00 00 a3 ?? ?? ?? ?? 8b 49 34 8b 50 14 ff 70 10 03 48 0c 03 d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}