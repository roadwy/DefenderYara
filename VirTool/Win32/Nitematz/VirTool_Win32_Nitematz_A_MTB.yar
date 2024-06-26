
rule VirTool_Win32_Nitematz_A_MTB{
	meta:
		description = "VirTool:Win32/Nitematz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 68 80 00 00 00 6a 03 57 57 68 00 00 00 80 50 ff 15 90 01 04 83 f8 ff 75 0e 8b 85 90 01 04 46 3b f3 7e b5 83 c8 ff 8b 4d fc 5f 5e 33 cd 5b e8 90 00 } //01 00 
		$a_03_1 = {8b f0 6a 00 56 57 ff 15 90 01 04 6a 00 8d 90 01 05 50 ff b5 f8 ef ff ff 8d 90 01 05 50 57 ff 15 90 01 04 6a 00 ff b5 f8 ef ff ff 6a 00 56 57 ff 15 90 01 04 6a 00 8d 90 01 05 50 68 00 10 00 00 8d 90 01 05 50 ff b5 f0 ef ff ff 90 00 } //01 00 
		$a_03_2 = {59 6a 0e 59 be 90 01 02 43 00 8b 54 24 0c 8d 90 01 03 f3 a5 6a 10 59 be 90 01 02 43 00 8d 90 01 06 f3 a5 6a 0f 59 66 a5 be 90 01 02 43 00 8d 90 01 03 f3 a5 8d 90 01 03 66 a5 e8 90 01 04 8b f0 83 cb ff 3b f3 90 00 } //01 00 
		$a_03_3 = {6a 02 59 cd 29 a3 90 01 04 89 0d 90 01 04 89 15 90 01 04 89 1d 90 01 04 89 35 90 01 04 89 3d 90 01 04 66 8c 15 90 01 04 66 8c 0d 90 01 04 66 8c 1d 90 01 04 66 8c 05 90 01 04 66 8c 25 90 01 04 66 8c 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}