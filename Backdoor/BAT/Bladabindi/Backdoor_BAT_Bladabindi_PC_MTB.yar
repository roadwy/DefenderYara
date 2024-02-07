
rule Backdoor_BAT_Bladabindi_PC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.PC!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 5f 61 76 61 73 74 } //01 00  Anti_avast
		$a_01_1 = {41 6e 74 69 5f 4b 61 73 70 65 72 73 6b 79 } //01 00  Anti_Kaspersky
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {4c 6f 61 64 46 69 6c 65 } //01 00  LoadFile
		$a_01_4 = {69 6e 6a 65 63 74 } //01 00  inject
		$a_01_5 = {4d 00 69 00 6e 00 73 00 74 00 6f 00 72 00 65 00 45 00 76 00 65 00 6e 00 74 00 73 00 2e 00 64 00 6c 00 6c 00 } //00 00  MinstoreEvents.dll
		$a_01_6 = {00 5d 04 00 } //00 05 
	condition:
		any of ($a_*)
 
}