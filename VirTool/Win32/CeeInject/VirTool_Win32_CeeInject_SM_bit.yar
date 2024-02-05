
rule VirTool_Win32_CeeInject_SM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c c1 e0 90 01 01 03 45 10 8b 4d 0c 03 4d 18 33 c1 8b 55 0c c1 ea 90 01 01 03 55 14 33 c2 8b 4d 08 8b 11 2b d0 8b 45 08 89 10 90 00 } //01 00 
		$a_03_1 = {33 ca 8b 45 90 01 01 c1 e8 90 01 01 03 45 90 01 01 33 c8 8b 55 90 01 01 2b d1 89 55 90 01 01 8b 45 90 01 01 50 8b 4d 90 01 01 51 8b 55 90 01 01 52 8b 45 90 01 01 50 8d 4d 90 01 01 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}