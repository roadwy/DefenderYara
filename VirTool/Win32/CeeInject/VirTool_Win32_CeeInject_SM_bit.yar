
rule VirTool_Win32_CeeInject_SM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c c1 e0 ?? 03 45 10 8b 4d 0c 03 4d 18 33 c1 8b 55 0c c1 ea ?? 03 55 14 33 c2 8b 4d 08 8b 11 2b d0 8b 45 08 89 10 } //1
		$a_03_1 = {33 ca 8b 45 ?? c1 e8 ?? 03 45 ?? 33 c8 8b 55 ?? 2b d1 89 55 ?? 8b 45 ?? 50 8b 4d ?? 51 8b 55 ?? 52 8b 45 ?? 50 8d 4d ?? 51 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}