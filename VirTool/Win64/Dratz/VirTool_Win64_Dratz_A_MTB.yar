
rule VirTool_Win64_Dratz_A_MTB{
	meta:
		description = "VirTool:Win64/Dratz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 32 00 00 00 66 89 85 82 02 00 00 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 b9 fa 00 00 00 ff 15 90 01 04 80 bd 99 08 00 00 00 74 90 00 } //01 00 
		$a_03_1 = {0f 11 45 c0 4c 89 7d d0 4c 89 7d d8 41 b8 07 00 00 00 48 8d 90 01 05 48 8d 90 01 02 e8 90 00 } //01 00 
		$a_03_2 = {0f 11 45 c0 4c 89 7d d0 4c 89 7d d8 41 b8 09 00 00 00 48 8d 90 01 05 48 8d 90 01 02 e8 90 00 } //01 00 
		$a_03_3 = {48 8b d0 48 8d 90 01 03 e8 90 01 04 48 8d 90 01 05 48 8b c8 e8 90 01 04 0f b6 d8 48 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}