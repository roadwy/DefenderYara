
rule VirTool_Win32_CeeInject_ABM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 fb e8 ?? ?? ?? ?? 8b 4e 04 03 c7 8a 14 08 32 d3 32 16 43 88 54 3c ?? 66 3b 5e 02 72 e1 } //1
		$a_03_1 = {0f b7 de e8 ?? ?? ?? ?? 8b 4f 04 03 c3 66 0f be 14 08 0f b6 07 66 33 d0 66 33 d6 b9 ?? ?? ?? ?? 66 23 d1 46 66 89 54 5d 00 66 3b 77 02 72 d1 } //1
		$a_03_2 = {03 f2 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8b 5c b4 ?? 0f b6 d2 89 5c 8c ?? 89 54 b4 ?? 8b 5c 8c ?? 03 da 81 e3 ?? ?? ?? ?? 79 08 4b 81 cb ?? ?? ?? ?? 43 0f b6 54 9c ?? 30 14 38 40 3b c5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}