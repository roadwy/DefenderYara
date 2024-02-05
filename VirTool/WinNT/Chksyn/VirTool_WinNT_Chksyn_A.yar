
rule VirTool_WinNT_Chksyn_A{
	meta:
		description = "VirTool:WinNT/Chksyn.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 03 00 "
		
	strings :
		$a_02_0 = {c6 45 f9 50 c6 45 fa 90 90 c6 45 fb c3 ff 15 90 01 02 01 00 88 45 f3 fa 0f 20 c0 90 00 } //01 00 
		$a_01_1 = {3d 04 c0 22 00 8b 4e 0c c7 46 1c 48 06 00 00 74 0a bf 10 00 00 c0 89 56 1c eb 20 } //01 00 
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 73 00 79 00 73 00 33 00 32 00 64 00 65 00 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_WinNT_Chksyn_A_2{
	meta:
		description = "VirTool:WinNT/Chksyn.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 17 04 00 00 c2 2c 00 85 c0 74 04 01 07 eb 0e c7 45 d8 0f 00 00 c0 eb db 8b de 89 5d d0 ff 75 e4 } //00 00 
	condition:
		any of ($a_*)
 
}