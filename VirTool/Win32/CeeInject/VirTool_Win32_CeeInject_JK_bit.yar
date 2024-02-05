
rule VirTool_Win32_CeeInject_JK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.JK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 56 8b 4c 24 0c 8b 74 24 10 8b 54 24 14 8b 44 24 18 85 f6 0f 95 c3 74 10 85 c0 74 0c 50 8a 02 30 01 58 42 41 4e 48 eb e9 } //01 00 
		$a_01_1 = {8b d7 03 50 24 8b c8 8b c7 03 41 1c 0f b7 14 72 03 3c 90 8b c7 } //00 00 
	condition:
		any of ($a_*)
 
}