
rule VirTool_Win32_CeeInject_gen_AS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 40 0f af c1 01 44 24 ?? ff 44 24 ?? 0f b7 ?? 06 83 44 24 ?? 28 39 44 24 ?? 0f 8c } //2
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_01_2 = {bb e8 03 00 00 0f b6 04 06 03 45 f8 } //1
		$a_01_3 = {83 45 f8 09 46 ff 45 fc 88 18 8b 45 fc 3b 45 10 0f 82 } //1
		$a_01_4 = {54 68 65 20 57 69 72 65 73 68 61 72 6b 20 4e 65 74 77 6f 72 6b 20 41 6e 61 6c 79 7a 65 72 00 } //1
		$a_03_5 = {6a 40 68 00 30 00 00 [0-0a] ff ?? 50 ff ?? 34 ff 74 24 ?? ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=5
 
}