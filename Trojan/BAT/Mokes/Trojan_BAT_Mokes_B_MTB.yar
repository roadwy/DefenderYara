
rule Trojan_BAT_Mokes_B_MTB{
	meta:
		description = "Trojan:BAT/Mokes.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 18 00 00 06 0a 06 02 28 05 00 00 06 7d 11 00 00 04 06 16 7d 12 00 00 04 06 16 7d 13 00 00 04 03 06 fe 06 19 00 00 06 73 22 00 00 0a 28 03 00 00 2b 2a } //01 00 
		$a_81_1 = {41 57 6b 43 5a 64 61 6f 64 77 } //01 00  AWkCZdaodw
		$a_81_2 = {58 4f 52 49 41 49 5a 43 4e 49 57 77 } //01 00  XORIAIZCNIWw
		$a_81_3 = {55 30 39 47 56 46 64 42 55 6b 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 } //01 00  U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu
		$a_81_4 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //01 00  DetectVirtualMachine
		$a_81_5 = {44 65 74 65 63 74 53 61 6e 64 62 6f 78 69 65 } //01 00  DetectSandboxie
		$a_81_6 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //01 00  DetectDebugger
		$a_81_7 = {43 68 65 63 6b 45 6d 75 6c 61 74 6f 72 } //01 00  CheckEmulator
		$a_81_8 = {52 75 6e 4f 6e 53 74 61 72 74 75 70 } //00 00  RunOnStartup
	condition:
		any of ($a_*)
 
}