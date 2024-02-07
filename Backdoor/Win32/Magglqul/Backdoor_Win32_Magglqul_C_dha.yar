
rule Backdoor_Win32_Magglqul_C_dha{
	meta:
		description = "Backdoor:Win32/Magglqul.C!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 53 00 53 00 4d 00 42 00 69 00 6f 00 73 00 5f 00 52 00 61 00 77 00 53 00 4d 00 42 00 69 00 6f 00 73 00 54 00 61 00 62 00 6c 00 65 00 73 00 } //01 00  MSSMBios_RawSMBiosTables
		$a_01_1 = {44 65 74 6f 75 72 54 72 61 6e 73 61 63 74 69 6f 6e 43 6f 6d 6d 69 74 20 46 61 69 6c 75 72 65 20 4f 6e 20 25 73 } //01 00  DetourTransactionCommit Failure On %s
		$a_01_2 = {41 63 63 6f 75 6e 74 20 4f 77 6e 65 72 20 4e 6f 74 20 46 6f 75 6e 64 20 46 6f 72 20 54 68 65 20 53 49 44 } //02 00  Account Owner Not Found For The SID
		$a_01_3 = {6d 61 67 67 69 65 } //01 00  maggie
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 } //01 00  Mozilla/4.0 (compatible)
		$a_01_5 = {53 4d 42 69 6f 73 44 61 74 61 } //01 00  SMBiosData
		$a_01_6 = {43 72 65 61 74 65 20 44 6f 77 6e 6c 6f 61 64 20 54 68 72 65 61 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //00 00  Create Download Thread Successfully
	condition:
		any of ($a_*)
 
}