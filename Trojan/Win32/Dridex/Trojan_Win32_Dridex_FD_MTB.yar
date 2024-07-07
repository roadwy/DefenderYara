
rule Trojan_Win32_Dridex_FD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //3 FFPGGLBM.pdb
		$a_81_1 = {57 54 48 65 6c 70 65 72 47 65 74 50 72 6f 76 53 69 67 6e 65 72 46 72 6f 6d 43 68 61 69 6e } //3 WTHelperGetProvSignerFromChain
		$a_81_2 = {4d 70 72 49 6e 66 6f 52 65 6d 6f 76 65 41 6c 6c } //3 MprInfoRemoveAll
		$a_81_3 = {53 65 74 75 70 53 65 74 46 69 6c 65 51 75 65 75 65 41 6c 74 65 72 6e 61 74 65 50 6c 61 74 66 6f 72 6d 57 } //3 SetupSetFileQueueAlternatePlatformW
		$a_81_4 = {64 6f 77 6e 6c 6f 61 64 } //3 download
		$a_81_5 = {54 68 65 54 61 66 } //3 TheTaf
		$a_81_6 = {48 69 6e 74 6f 34 35 69 } //3 Hinto45i
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}