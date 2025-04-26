
rule VirTool_Win32_CeeInject_BAD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b ?? 08 c1 ?? 05 03 ?? 14 33 ?? 5d c3 } //1
		$a_03_1 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 14 33 c1 8b ?? 08 c1 ?? 05 03 ?? 10 33 } //1
		$a_01_2 = {89 55 fc 8b 45 fc c1 e0 04 03 45 e4 8b 4d fc 03 4d f4 33 c1 8b 55 fc c1 ea 05 03 55 e0 33 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}