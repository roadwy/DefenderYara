
rule VirTool_Win32_CeeInject_NB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8a 94 0d b4 d2 ff ff 33 c2 8b 4d fc } //1
		$a_03_1 = {70 f8 27 41 6a ?? 8d 95 d4 df ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_NB_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.NB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 ?? 03 4c 24 ?? 8b d7 c1 e2 ?? 03 54 24 ?? 8d 04 3b 33 ca 33 c8 6a 00 2b f1 ff 15 ?? ?? ?? ?? 8b ce c1 e9 ?? 03 4c 24 ?? 8b d6 c1 e2 ?? 03 54 24 ?? 8d 04 33 33 ca 33 c8 2b f9 81 c3 ?? ?? ?? ?? 83 ed 01 75 } //1
		$a_03_1 = {8a 14 06 88 10 8b 55 ?? 41 40 3b ca 72 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}