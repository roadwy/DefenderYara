
rule VirTool_MacOS_MythicPoseidon_A_MTB{
	meta:
		description = "VirTool:MacOS/MythicPoseidon.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 73 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //01 00  main.sendFileToMythic
		$a_00_1 = {6d 61 69 6e 2e 68 61 6e 64 6c 65 52 65 6d 6f 76 65 49 6e 74 65 72 6e 61 6c 54 43 50 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //01 00  main.handleRemoveInternalTCPConnections
		$a_00_2 = {2f 70 6f 73 65 69 64 6f 6e 2e 67 6f } //01 00  /poseidon.go
		$a_00_3 = {2f 70 6f 72 74 73 63 61 6e 2e 67 6f } //00 00  /portscan.go
	condition:
		any of ($a_*)
 
}