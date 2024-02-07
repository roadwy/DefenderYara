
rule Trojan_BAT_AgentTesla_LVN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 8e 69 8d 90 01 04 0b 16 0c 2b 17 00 08 06 8e 69 5d 0d 07 08 02 08 91 06 09 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d dd 90 00 } //01 00 
		$a_01_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_4 = {56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 57 72 69 74 65 } //01 00  VirtualMemoryWrite
		$a_01_5 = {54 48 52 45 41 44 5f 48 49 4a 41 43 4b } //01 00  THREAD_HIJACK
		$a_01_6 = {2d 00 2d 00 2d 00 20 00 5e 00 2e 00 2d 00 2d 00 2e } //00 00 
	condition:
		any of ($a_*)
 
}