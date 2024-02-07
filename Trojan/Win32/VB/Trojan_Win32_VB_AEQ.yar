
rule Trojan_Win32_VB_AEQ{
	meta:
		description = "Trojan:Win32/VB.AEQ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 57 00 6f 00 72 00 6b 00 5c 00 74 00 65 00 73 00 74 00 5c 00 53 00 75 00 6d 00 6d 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //01 00  \Work\test\Summer.vbp
		$a_01_1 = {59 00 45 00 53 00 2e 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 } //01 00  YES.infected
		$a_01_2 = {4e 00 74 00 57 00 72 00 69 00 74 00 65 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00  NtWriteVirtualMemory
		$a_01_3 = {41 00 70 00 70 00 65 00 6e 00 64 00 43 00 68 00 75 00 6e 00 6b 00 } //00 00  AppendChunk
	condition:
		any of ($a_*)
 
}