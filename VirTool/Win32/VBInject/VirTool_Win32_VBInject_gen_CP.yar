
rule VirTool_Win32_VBInject_gen_CP{
	meta:
		description = "VirTool:Win32/VBInject.gen!CP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 04 06 cc 03 c1 eb ?? 8d 45 ?? 50 c6 45 ?? 58 e8 ?? ?? ?? ?? 8d 4d ?? 51 c6 45 ?? 59 90 13 a1 ?? ?? ?? ?? 8b 50 14 8b 48 0c 2b ca 8b 54 24 04 8a 02 8b 15 ?? ?? ?? ?? 88 04 11 ff ?? ?? ?? ?? 00 c2 04 00 } //2
		$a_03_1 = {8a 04 13 8b 55 00 8b 72 14 8a 0c 08 8b 42 0c 8b 15 ?? ?? ?? ?? 2b c6 03 d0 88 0d ?? ?? ?? ?? 30 0a 8b 0d } //1
		$a_03_2 = {ff ff 00 30 00 00 2b 48 14 8d 95 ?? ?? ff ff c1 e1 04 03 48 0c ff d7 8b 85 ?? ?? ff ff c7 85 ?? ?? ff ff 40 00 00 00 c7 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}