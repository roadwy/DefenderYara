
rule VirTool_Win32_CeeInject_AAY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 04 8b c2 c1 e0 04 8b ca 03 44 24 08 c1 e9 05 03 4c 24 10 33 c1 8b 4c 24 0c 03 ca 33 c1 } //1
		$a_03_1 = {8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}