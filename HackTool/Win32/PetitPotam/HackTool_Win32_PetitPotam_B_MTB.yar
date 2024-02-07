
rule HackTool_Win32_PetitPotam_B_MTB{
	meta:
		description = "HackTool:Win32/PetitPotam.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 36 00 38 00 31 00 64 00 34 00 38 00 38 00 2d 00 64 00 38 00 35 00 30 00 2d 00 31 00 31 00 64 00 30 00 2d 00 38 00 63 00 35 00 32 00 2d 00 30 00 30 00 63 00 30 00 34 00 66 00 64 00 39 00 30 00 66 00 37 00 65 00 } //01 00  c681d488-d850-11d0-8c52-00c04fd90f7e
		$a_01_1 = {45 66 73 52 70 63 4f 70 65 6e 46 69 6c 65 52 61 77 } //01 00  EfsRpcOpenFileRaw
		$a_01_2 = {45 66 73 52 70 63 45 6e 63 72 79 70 74 46 69 6c 65 53 72 76 } //01 00  EfsRpcEncryptFileSrv
		$a_01_3 = {45 66 73 52 70 63 44 65 63 72 79 70 74 46 69 6c 65 53 72 76 } //01 00  EfsRpcDecryptFileSrv
		$a_01_4 = {45 66 73 52 70 63 51 75 65 72 79 55 73 65 72 73 4f 6e 46 69 6c 65 } //01 00  EfsRpcQueryUsersOnFile
		$a_01_5 = {45 66 73 52 70 63 51 75 65 72 79 52 65 63 6f 76 65 72 79 41 67 65 6e 74 73 } //01 00  EfsRpcQueryRecoveryAgents
		$a_01_6 = {45 66 73 52 70 63 52 65 6d 6f 76 65 55 73 65 72 73 46 72 6f 6d 46 69 6c 65 } //01 00  EfsRpcRemoveUsersFromFile
		$a_01_7 = {45 66 73 52 70 63 41 64 64 55 73 65 72 73 54 6f 46 69 6c 65 } //01 00  EfsRpcAddUsersToFile
		$a_01_8 = {50 65 74 69 74 50 6f 74 61 6d 2e 65 78 65 } //01 00  PetitPotam.exe
		$a_01_9 = {74 00 6f 00 70 00 6f 00 74 00 61 00 6d 00 } //00 00  topotam
	condition:
		any of ($a_*)
 
}