
rule VirTool_Win64_PoolParty_A_MTB{
	meta:
		description = "VirTool:Win64/PoolParty.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 b9 00 30 00 00 41 b8 f0 00 00 00 48 8b 08 ff 15 } //1
		$a_80_1 = {50 6f 6f 6c 50 61 72 74 79 45 76 65 6e 74 } //PoolPartyEvent  1
		$a_80_2 = {52 50 43 20 43 6f 6e 74 72 6f 6c 5c 50 6f 6f 6c 50 61 72 74 79 41 4c 50 43 50 6f 72 74 } //RPC Control\PoolPartyALPCPort  1
		$a_80_3 = {50 6f 6f 6c 50 61 72 74 79 4a 6f 62 } //PoolPartyJob  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}