
rule Backdoor_Win64_Bazarldr_DB_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0a 00 00 0a 00 "
		
	strings :
		$a_81_0 = {50 44 48 20 43 6f 75 6e 74 65 72 20 53 74 61 74 69 73 74 69 63 73 20 44 65 6d 6f 6e 73 74 72 61 74 69 6f 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e } //0a 00  PDH Counter Statistics Demonstration Application
		$a_81_1 = {70 64 68 2e 64 6c 6c } //0a 00  pdh.dll
		$a_81_2 = {53 74 61 74 6c 69 73 74 } //01 00  Statlist
		$a_81_3 = {50 64 68 43 6f 6d 70 75 74 65 43 6f 75 6e 74 65 72 53 74 61 74 69 73 74 69 63 73 } //01 00  PdhComputeCounterStatistics
		$a_81_4 = {50 64 68 43 6f 6c 6c 65 63 74 51 75 65 72 79 44 61 74 61 } //01 00  PdhCollectQueryData
		$a_81_5 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //01 00  PostQuitMessage
		$a_81_6 = {44 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 41 } //01 00  DispatchMessageA
		$a_81_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_81_8 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //01 00  ClientToScreen
		$a_81_9 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
		$a_00_10 = {5d 04 00 00 56 76 04 80 5c 34 00 00 57 76 04 80 00 00 01 00 06 00 1e 00 42 61 63 6b 64 6f } //6f 72 
	condition:
		any of ($a_*)
 
}