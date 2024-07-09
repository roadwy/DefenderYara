
rule VirTool_Win32_CeeInject_gen_IL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8d 4d ?? 51 89 55 ?? 8b 40 0d 6a 00 8d 55 ?? 89 45 ?? 8b 45 ?? 52 50 ff 15 } //1
		$a_01_1 = {6a 40 68 00 30 00 00 8d 41 08 50 0f b6 42 02 50 8b 01 8d 51 04 52 50 ff 15 } //1
		$a_01_2 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //1
		$a_01_3 = {5a 77 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}