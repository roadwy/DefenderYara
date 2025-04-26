
rule VirTool_Win32_CeeInject_gen_HP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 ff 57 68 00 30 00 00 ff 76 50 ff 76 34 ff 35 ?? ?? ?? ?? e8 } //1
		$a_03_1 = {0f b7 4e 06 3b c1 72 90 09 0b 00 a1 ?? ?? ?? ?? 40 a3 } //1
		$a_03_2 = {8b 46 28 03 46 34 89 (84 24 ?? ?? ??|?? 45 ?? 8d) (|) 44 24 45 } //1
		$a_03_3 = {33 db 53 68 00 30 00 00 ff 76 50 e8 ?? ?? ?? ?? 53 ff 76 54 57 ff 76 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}