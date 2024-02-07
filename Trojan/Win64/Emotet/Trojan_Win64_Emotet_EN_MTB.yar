
rule Trojan_Win64_Emotet_EN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 0c 01 32 0c 2b 88 0b 48 ff c3 48 83 ee 01 75 be } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EN_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 99 b9 41 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EN_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //02 00  WaitForSingleObject
		$a_01_3 = {6b 4c 31 5a 37 66 34 58 53 57 5a 70 62 69 49 4f 64 7a 61 4e 77 6d 56 6b } //02 00  kL1Z7f4XSWZpbiIOdzaNwmVk
		$a_01_4 = {4d 6e 46 33 6a 70 45 70 4d 58 4e 79 73 51 68 62 74 78 61 62 50 53 4a 56 6a 66 35 6c 36 5a 36 58 63 65 43 72 32 6b 4b 74 71 49 64 6c } //00 00  MnF3jpEpMXNysQhbtxabPSJVjf5l6Z6XceCr2kKtqIdl
	condition:
		any of ($a_*)
 
}