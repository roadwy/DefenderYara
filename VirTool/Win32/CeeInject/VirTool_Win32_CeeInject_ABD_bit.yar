
rule VirTool_Win32_CeeInject_ABD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 c0 00 00 00 0b d0 88 55 ?? 0f b6 4d ?? 0f b6 55 ?? c1 e2 06 81 e2 c0 00 00 00 0b ca 88 4d ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 } //1
		$a_03_1 = {8b 55 08 8b 02 8b 4d ?? 8a 54 01 03 88 55 ?? 0f b6 45 ?? 0f b6 4d ?? c1 e1 02 81 e1 c0 00 00 00 0b c1 88 45 ?? 0f b6 55 ?? 0f b6 45 ?? c1 e0 04 } //1
		$a_01_2 = {0f b6 c8 8b 55 08 03 55 0c 0f be 02 33 c1 8b 4d 08 03 4d 0c 88 01 8b 55 0c 83 ea 01 89 55 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}