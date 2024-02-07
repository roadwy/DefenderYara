
rule Trojan_BAT_AgentTesla_NT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 19 00 00 0a 8c 90 01 03 1b 2d 0a 28 90 01 03 2b 80 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {53 65 74 50 72 6f 6a 65 63 74 45 72 72 6f 72 } //01 00  SetProjectError
		$a_01_2 = {43 6c 65 61 72 50 72 6f 6a 65 63 74 45 72 72 6f 72 } //01 00  ClearProjectError
		$a_01_3 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_01_4 = {44 41 54 41 43 45 4e 54 45 52 45 4e 43 } //00 00  DATACENTERENC
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 42 5f 62 6c 61 63 6b 6a 61 63 6b 2e 42 61 73 65 5f 54 61 62 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  VB_blackjack.Base_Table.resources
		$a_81_1 = {4c 6f 63 6b 48 6f 6c 64 65 72 } //01 00  LockHolder
		$a_81_2 = {55 6e 6d 61 6e 61 67 65 64 46 75 6e 63 74 69 6f 6e } //01 00  UnmanagedFunction
		$a_81_3 = {42 6f 75 6e 64 48 61 6e 64 6c 65 } //01 00  BoundHandle
		$a_81_4 = {50 6f 69 6e 74 65 72 41 74 74 72 69 62 75 74 65 } //01 00  PointerAttribute
		$a_81_5 = {67 65 74 5f 53 65 74 74 69 6e 67 78 } //01 00  get_Settingx
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}