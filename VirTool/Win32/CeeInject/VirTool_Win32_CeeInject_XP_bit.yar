
rule VirTool_Win32_CeeInject_XP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 ef be ad de e8 90 02 04 89 04 24 8b 1c 24 43 39 0b 75 fb 90 00 } //01 00 
		$a_01_1 = {8b 4b 04 89 4c 24 04 8b 4b 08 89 4c 24 08 83 c3 0c 89 5c 24 0c 33 db 8b 54 24 0c 8b 12 33 d3 3b 54 24 08 74 03 43 eb ef } //01 00 
		$a_01_2 = {8b 54 24 0c 33 c9 31 1c 0a 3b 4c 24 04 7d 05 83 c1 04 eb f2 8b e5 5d 5b ff e2 } //00 00 
	condition:
		any of ($a_*)
 
}