
rule Backdoor_BAT_Crysan_ABI_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 95 02 28 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 38 00 00 00 51 00 00 00 4e 00 00 00 b6 00 00 00 04 00 00 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_01_2 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00  get_IsAttached
		$a_01_3 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_7 = {4c 78 65 6f 6d 72 63 63 77 6c 6b 6d 66 37 2e 65 78 65 } //01 00  Lxeomrccwlkmf7.exe
		$a_01_8 = {24 31 37 32 63 32 64 66 32 2d 33 36 66 65 2d 34 33 38 34 2d 62 34 34 30 2d 62 65 30 34 63 62 36 38 65 34 63 63 } //00 00  $172c2df2-36fe-4384-b440-be04cb68e4cc
	condition:
		any of ($a_*)
 
}