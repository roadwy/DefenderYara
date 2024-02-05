
rule VirTool_Win32_Reflexon_A_MTB{
	meta:
		description = "VirTool:Win32/Reflexon.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 40 40 4c 8b d1 b8 66 c7 40 48 0f 05 c6 40 4a c3 89 70 44 48 83 e8 80 c7 00 4c 8b d1 b8 66 c7 40 08 0f 05 c6 40 0a c3 89 68 04 48 89 90 01 05 48 8d 90 01 05 c7 00 4c 8b d1 b8 66 c7 40 08 0f 05 c6 40 0a c3 89 58 04 90 00 } //01 00 
		$a_03_1 = {81 79 40 4c 8b d1 b8 90 01 02 ff c2 41 3b d1 90 01 02 e9 90 01 04 66 41 ff c0 66 45 3b c3 0f 90 00 } //01 00 
		$a_03_2 = {48 89 bc 24 10 01 00 00 33 ff 48 8d 90 01 05 49 8b cf 89 7d eb 89 7d 03 0f 11 45 2f ff 15 90 01 04 48 85 c0 0f 84 90 01 04 48 8d 90 01 05 48 8d 90 01 04 48 8d 90 01 02 c7 45 e7 30 00 00 00 0f 57 c0 48 89 45 f7 90 00 } //01 00 
		$a_03_3 = {33 c9 ba 00 01 00 00 41 b8 00 30 00 00 44 8d 90 01 02 ff 15 90 01 04 48 8b c8 48 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}