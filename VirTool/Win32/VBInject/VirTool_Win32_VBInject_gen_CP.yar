
rule VirTool_Win32_VBInject_gen_CP{
	meta:
		description = "VirTool:Win32/VBInject.gen!CP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 04 06 cc 03 c1 eb 90 01 01 8d 45 90 01 01 50 c6 45 90 01 01 58 e8 90 01 04 8d 4d 90 01 01 51 c6 45 90 01 01 59 90 13 a1 90 01 04 8b 50 14 8b 48 0c 2b ca 8b 54 24 04 8a 02 8b 15 90 01 04 88 04 11 ff 90 01 04 00 c2 04 00 90 00 } //2
		$a_03_1 = {8a 04 13 8b 55 00 8b 72 14 8a 0c 08 8b 42 0c 8b 15 90 01 04 2b c6 03 d0 88 0d 90 01 04 30 0a 8b 0d 90 00 } //1
		$a_03_2 = {ff ff 00 30 00 00 2b 48 14 8d 95 90 01 02 ff ff c1 e1 04 03 48 0c ff d7 8b 85 90 01 02 ff ff c7 85 90 01 02 ff ff 40 00 00 00 c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}