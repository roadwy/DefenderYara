
rule VirTool_Win64_Luidek_A_MTB{
	meta:
		description = "VirTool:Win64/Luidek.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 6c 24 90 01 01 48 8d 90 02 10 48 89 90 01 01 24 90 02 20 e8 90 02 05 48 8b 90 02 05 48 89 90 01 01 24 48 c7 90 01 01 24 08 00 00 00 00 48 8b 90 01 01 24 90 01 01 48 89 90 01 01 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 90 00 } //01 00 
		$a_81_1 = {6c 75 70 6f 2f 6c 75 70 6f 2d 63 6c 69 65 6e 74 2f 63 6d 64 2e 52 65 73 70 6f 6e 73 65 } //01 00  lupo/lupo-client/cmd.Response
		$a_81_2 = {6c 75 70 6f 2f 6c 75 70 6f 2d 63 6c 69 65 6e 74 2f 63 6f 72 65 } //01 00  lupo/lupo-client/core
		$a_81_3 = {6c 75 70 6f 2d 73 65 72 76 65 72 2f 63 6f 72 65 2e 53 65 73 73 69 6f 6e 73 } //00 00  lupo-server/core.Sessions
	condition:
		any of ($a_*)
 
}