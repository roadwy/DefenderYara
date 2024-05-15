
rule VirTool_Win32_Threqesz_A_MTB{
	meta:
		description = "VirTool:Win32/Threqesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 85 f6 90 01 06 8b 3d 18 20 40 00 90 01 05 56 90 01 02 a3 74 43 40 00 85 c0 90 02 11 56 90 01 02 83 3d 74 43 40 00 00 a3 78 43 40 00 90 01 06 85 c0 90 00 } //01 00 
		$a_03_1 = {6a 40 68 00 10 00 00 68 e4 00 00 00 b9 39 00 00 00 90 01 06 be c0 21 40 00 f3 a5 6a 00 90 01 06 8b f8 89 bd ec f7 ff ff 85 ff 90 00 } //01 00 
		$a_03_2 = {8b e5 5d c3 57 90 02 10 83 c4 08 90 01 06 b9 39 00 00 00 f3 a5 90 01 06 68 28 23 40 00 8b f0 90 01 02 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}