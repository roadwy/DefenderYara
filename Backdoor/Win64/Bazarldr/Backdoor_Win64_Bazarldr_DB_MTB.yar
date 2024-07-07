
rule Backdoor_Win64_Bazarldr_DB_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0a 00 00 "
		
	strings :
		$a_81_0 = {50 44 48 20 43 6f 75 6e 74 65 72 20 53 74 61 74 69 73 74 69 63 73 20 44 65 6d 6f 6e 73 74 72 61 74 69 6f 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e } //10 PDH Counter Statistics Demonstration Application
		$a_81_1 = {70 64 68 2e 64 6c 6c } //10 pdh.dll
		$a_81_2 = {53 74 61 74 6c 69 73 74 } //10 Statlist
		$a_81_3 = {50 64 68 43 6f 6d 70 75 74 65 43 6f 75 6e 74 65 72 53 74 61 74 69 73 74 69 63 73 } //1 PdhComputeCounterStatistics
		$a_81_4 = {50 64 68 43 6f 6c 6c 65 63 74 51 75 65 72 79 44 61 74 61 } //1 PdhCollectQueryData
		$a_81_5 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //1 PostQuitMessage
		$a_81_6 = {44 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 41 } //1 DispatchMessageA
		$a_81_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_81_8 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //1 ClientToScreen
		$a_81_9 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=37
 
}