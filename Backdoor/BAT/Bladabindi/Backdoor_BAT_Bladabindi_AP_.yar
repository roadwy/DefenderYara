
rule Backdoor_BAT_Bladabindi_AP_{
	meta:
		description = "Backdoor:BAT/Bladabindi.AP!!Bladabindi,SIGNATURE_TYPE_ARHSTR_EXT,0f 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtSetInformationProcess
		$a_01_1 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //1 capGetDriverDescriptionA
		$a_01_2 = {67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e } //1 get_ShiftKeyDown
		$a_01_3 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_03_4 = {1f 1d 0f 00 1a 28 ?? 00 00 06 } //10
		$a_03_5 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*10+(#a_03_5  & 1)*1) >=14
 
}