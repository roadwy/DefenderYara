
rule Trojan_BAT_SpySnake_MAJ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 00 47 00 35 00 6a 00 5a 00 32 00 46 00 33 00 51 00 33 00 39 00 72 00 62 00 48 00 70 00 2f 00 5a 00 57 00 4a 00 67 00 4e 00 54 00 41 00 3d 00 } //1 TG5jZ2F3Q39rbHp/ZWJgNTA=
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {41 63 74 69 6f 6e 42 6c 6f 63 6b } //1 ActionBlock
		$a_01_3 = {4f 6e 44 69 73 61 62 6c 65 64 } //1 OnDisabled
		$a_01_4 = {49 52 65 6d 6f 74 65 54 65 73 74 44 69 73 63 6f 76 65 72 79 53 65 72 76 69 63 65 } //1 IRemoteTestDiscoveryService
		$a_01_5 = {53 65 74 53 74 61 74 65 4d 61 63 68 69 6e 65 } //1 SetStateMachine
		$a_01_6 = {67 65 74 5f 4c 6f 67 5f 42 75 6c 6b 5f 41 6e 61 6c 79 73 69 73 5f 53 6f 6c 75 74 69 6f 6e 5f 53 6e 61 70 73 68 6f 74 5f 4d 69 73 73 69 6e 67 } //1 get_Log_Bulk_Analysis_Solution_Snapshot_Missing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}