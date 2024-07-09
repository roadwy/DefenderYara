
rule Trojan_BAT_AgentTesla_LVN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 8e 69 8d ?? ?? ?? ?? 0b 16 0c 2b 17 00 08 06 8e 69 5d 0d 07 08 02 08 91 06 09 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d dd } //1
		$a_01_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 57 72 69 74 65 } //1 VirtualMemoryWrite
		$a_01_5 = {54 48 52 45 41 44 5f 48 49 4a 41 43 4b } //1 THREAD_HIJACK
		$a_01_6 = {2d 00 2d 00 2d 00 20 00 5e 00 2e 00 2d 00 2d 00 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}