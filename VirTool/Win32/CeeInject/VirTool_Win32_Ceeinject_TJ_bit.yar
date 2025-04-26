
rule VirTool_Win32_Ceeinject_TJ_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.TJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 03 8a 00 34 7b 8b 15 ?? ?? ?? ?? 03 13 88 02 90 90 ff 03 81 3b 5d 57 00 00 75 e0 90 09 05 00 a1 } //1
		$a_01_1 = {8b 03 40 bf 8a 00 00 00 33 d2 f7 f7 8b c1 03 03 88 10 90 ff 03 81 3b 57 b9 46 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Ceeinject_TJ_bit_2{
	meta:
		description = "VirTool:Win32/Ceeinject.TJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 8b 7c 24 0c 8b 4c 24 10 8b 74 24 14 8b 54 24 18 85 d2 74 0e ac 52 30 07 5a 4a 47 e2 f3 5e 5b 33 c0 c3 } //1
		$a_01_1 = {48 89 5c 24 08 57 48 83 ec 20 48 8b 41 10 48 8b f9 48 8b 00 48 3b 47 10 74 33 80 78 18 00 74 f1 48 8b 18 48 3b 47 10 74 1f 48 8b 48 08 48 89 19 48 8b 48 08 48 8b 10 48 89 4a 08 48 8b c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}