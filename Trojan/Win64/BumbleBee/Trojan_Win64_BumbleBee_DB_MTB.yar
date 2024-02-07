
rule Trojan_Win64_BumbleBee_DB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 67 67 6f 6a 78 32 38 39 63 69 30 2e 64 6c 6c } //0a 00  cggojx289ci0.dll
		$a_01_1 = {61 6d 61 65 66 6a 6a 31 38 33 78 69 2e 64 6c 6c } //0a 00  amaefjj183xi.dll
		$a_01_2 = {73 6c 77 31 38 39 6e 6a 32 31 2e 64 6c 6c } //01 00  slw189nj21.dll
		$a_01_3 = {49 73 53 79 73 74 65 6d 52 65 73 75 6d 65 41 75 74 6f 6d 61 74 69 63 } //01 00  IsSystemResumeAutomatic
		$a_01_4 = {51 75 65 72 79 49 64 6c 65 50 72 6f 63 65 73 73 6f 72 43 79 63 6c 65 54 69 6d 65 } //01 00  QueryIdleProcessorCycleTime
		$a_01_5 = {44 65 6c 65 74 65 46 69 62 65 72 } //01 00  DeleteFiber
		$a_01_6 = {49 74 65 72 6e 61 6c 4a 6f 62 } //01 00  IternalJob
		$a_01_7 = {53 65 74 50 61 74 68 } //00 00  SetPath
	condition:
		any of ($a_*)
 
}