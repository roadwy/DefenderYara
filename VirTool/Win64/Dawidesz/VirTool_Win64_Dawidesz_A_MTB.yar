
rule VirTool_Win64_Dawidesz_A_MTB{
	meta:
		description = "VirTool:Win64/Dawidesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 7c 24 50 0f 11 01 88 41 10 33 c0 0f 57 c0 48 89 44 24 70 48 b8 00 00 00 00 10 10 00 00 48 c7 45 10 11 01 00 00 0f 11 45 90 } //01 00 
		$a_01_1 = {0f 11 41 80 0f 10 40 a0 0f 11 49 90 0f 10 48 b0 0f 11 41 a0 0f 10 40 c0 0f 11 49 b0 0f 10 48 d0 0f 11 41 c0 0f 10 40 e0 0f 11 49 d0 0f 10 48 f0 0f 11 41 e0 0f 11 49 f0 48 83 ea 01 75 ad } //01 00 
		$a_03_2 = {48 8b d8 ff 15 90 01 04 48 8b c8 48 8d 90 01 05 ff 15 90 01 04 48 90 01 04 45 33 c9 48 89 4c 24 48 45 90 00 } //01 00 
		$a_03_3 = {48 8b cb e8 90 01 04 48 90 01 03 ff 15 90 01 04 48 81 45 08 00 e1 f5 05 48 90 01 03 b1 01 ff 15 90 01 04 85 c0 79 90 00 } //01 00 
		$a_03_4 = {48 89 bc 24 a0 02 00 00 ff 15 90 01 04 8b d8 ff 15 90 01 04 4c 90 01 04 ba 20 00 00 00 48 8b c8 ff 15 90 01 04 33 ff 85 c0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}