
rule Trojan_BAT_RedLineStealer_MAX_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {4e 61 6f 6c 71 4b 72 68 6c 6a 54 } //1 NaolqKrhljT
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_2 = {65 4f 63 43 54 77 65 72 69 7a 47 56 71 58 5a 68 73 4c 73 5a } //1 eOcCTwerizGVqXZhsLsZ
		$a_01_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_5 = {57 00 6f 00 77 00 36 00 34 00 47 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //1 Wow64GetThreadContext
		$a_01_6 = {52 00 65 00 61 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 ReadProcessMemory
		$a_01_7 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 } //1 VirtualAllocEx
		$a_01_8 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 WriteProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}