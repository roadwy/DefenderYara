
rule VirTool_Win32_CeeInject_BAH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 1b 53 c6 44 24 1c 79 c6 44 24 1e 74 88 4c 24 1f c6 44 24 20 6d c6 44 24 21 33 c6 44 24 22 32 88 54 24 23 c6 44 24 25 76 c6 44 24 26 63 c6 44 24 27 68 c6 44 24 28 6f c6 44 24 2a 74 c6 44 24 2b 2e 88 4c 24 2c c6 44 24 2d 78 88 4c 24 2e c6 44 24 2f 00 } //01 00 
		$a_01_1 = {b2 5c 88 44 24 11 88 44 24 15 b1 65 88 44 24 1c 88 44 24 21 } //00 00 
	condition:
		any of ($a_*)
 
}