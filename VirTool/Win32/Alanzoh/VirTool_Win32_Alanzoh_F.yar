
rule VirTool_Win32_Alanzoh_F{
	meta:
		description = "VirTool:Win32/Alanzoh.F,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {6f 72 69 67 69 6e 61 6c 5f 73 65 73 73 69 6f 6e 5f 6b 65 79 } //01 00  original_session_key
		$a_81_1 = {6b 65 79 5f 69 74 65 72 61 74 69 6f 6e } //01 00  key_iteration
		$a_81_2 = {61 63 74 69 76 65 5f 73 65 72 76 65 72 } //01 00  active_server
		$a_81_3 = {73 65 73 73 69 6f 6e 5f 69 64 } //01 00  session_id
		$a_02_4 = {89 c7 01 df 0f 10 05 90 01 04 0f 29 84 24 e0 02 00 00 0f 10 05 90 01 04 0f 29 84 24 d0 02 00 00 0f 10 05 90 01 04 0f 29 84 24 c0 02 00 00 f3 0f 6f 05 90 01 04 66 0f 7f 84 24 b0 02 00 00 8d 9c 24 b0 02 00 00 53 e8 90 01 04 83 c4 04 01 e0 05 b0 02 00 00 50 6a 20 89 7c 24 1c 57 e8 90 01 04 83 c4 0c 68 00 40 00 00 53 e8 90 01 04 83 c4 08 84 c0 0f 84 90 01 04 53 e8 90 01 04 83 c4 04 85 c0 0f 84 90 01 04 89 c7 6a 01 68 00 10 00 00 e8 90 01 04 83 c4 08 90 00 } //01 00 
		$a_02_5 = {83 c4 04 01 e0 05 28 05 00 00 8b 4c 24 14 83 c1 05 50 6a 1e 51 e8 90 01 04 83 c4 0c 57 e8 90 01 04 83 c4 04 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}