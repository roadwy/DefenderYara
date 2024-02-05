
rule VirTool_Win32_CeeInject_gen_KI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 41 3c 0f b7 54 08 14 03 c1 0f b7 48 06 53 03 d0 56 8d 34 89 8d 44 f2 90 01 01 33 d2 85 c9 76 0f 8a 58 90 01 01 84 db 74 0a 42 83 e8 28 3b d1 72 f1 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}