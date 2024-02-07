
rule Backdoor_Win32_Bladabindi_AA_MTB{
	meta:
		description = "Backdoor:Win32/Bladabindi.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 50 61 73 73 77 6f 72 64 } //03 00  DecryptPassword
		$a_81_1 = {67 65 74 4d 61 69 6c 73 20 66 75 6e 63 20 73 74 61 72 74 } //03 00  getMails func start
		$a_81_2 = {47 6f 74 6f 20 6b 69 6c 6c 69 6e 67 20 6f 75 74 6c 6f 6f 6b 20 70 72 6f 63 65 73 73 } //03 00  Goto killing outlook process
		$a_81_3 = {41 66 74 6b 65 72 20 53 6c 65 65 70 65 64 } //03 00  Aftker Sleeped
		$a_81_4 = {44 65 62 75 67 2e 74 78 74 } //03 00  Debug.txt
		$a_81_5 = {72 75 73 73 6b 31 38 } //03 00  russk18
		$a_81_6 = {67 65 74 4d 61 69 6c 73 20 66 75 6e 63 20 72 65 74 75 72 6e 69 6e 67 } //00 00  getMails func returning
	condition:
		any of ($a_*)
 
}