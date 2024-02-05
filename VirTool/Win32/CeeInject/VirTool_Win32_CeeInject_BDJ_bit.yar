
rule VirTool_Win32_CeeInject_BDJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 4c c6 85 90 01 03 ff 6f c6 85 90 01 03 ff 63 c6 85 90 01 03 ff 6c c6 85 90 01 03 ff 6c c6 85 90 01 03 ff 61 c6 85 90 01 03 ff 41 c6 85 90 01 03 ff 6f c6 85 90 01 03 ff 63 90 00 } //01 00 
		$a_01_1 = {8b d7 c1 ea 05 03 54 24 20 8b c7 c1 e0 04 03 c1 33 d0 8d 04 3b 33 d0 2b f2 8b d6 c1 ea 05 03 54 24 18 8b c6 c1 e0 04 03 c5 33 d0 8d 04 33 33 d0 2b fa } //00 00 
	condition:
		any of ($a_*)
 
}