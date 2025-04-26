
rule Backdoor_BAT_Bladabindi_AR_{
	meta:
		description = "Backdoor:BAT/Bladabindi.AR!!Bladabindi,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_03_0 = {1f 1d 0f 01 1a 28 ?? 00 00 06 } //10
		$a_03_1 = {20 a0 00 00 00 [0-30] 20 a1 00 00 00 [0-30] 20 00 00 01 00 [0-30] 1f 10 [0-30] 20 00 00 02 00 [0-30] 1f 11 [0-30] 20 a3 00 00 00 } //1
		$a_03_2 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06 } //1
		$a_01_3 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtSetInformationProcess
		$a_01_4 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //1 capGetDriverDescriptionA
		$a_01_5 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}