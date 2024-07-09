
rule VirTool_Win32_CeeInject_BCB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BCB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 14 33 c1 8b 4d 08 c1 e9 05 03 4d 10 33 c1 5d c3 } //1
		$a_01_1 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b 4d 08 c1 e9 05 03 4d 14 33 c1 5d } //1
		$a_03_2 = {6a 6b 58 8b 4d cc 66 89 04 4d ?? ?? ?? ?? 8b 45 cc 40 89 45 cc 6a 65 58 8b 4d cc 66 89 04 4d ?? ?? ?? ?? 8b 45 cc 40 89 45 cc 6a 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}