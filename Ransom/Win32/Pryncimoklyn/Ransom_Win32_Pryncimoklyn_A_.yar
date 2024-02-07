
rule Ransom_Win32_Pryncimoklyn_A_{
	meta:
		description = "Ransom:Win32/Pryncimoklyn.A!!Pryncimoklyn.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 36 85 c9 74 90 01 01 c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75 90 00 } //01 00 
		$a_80_1 = {30 30 41 45 25 30 38 58 } //00AE%08X  01 00 
		$a_80_2 = {2f 73 63 72 69 70 74 73 2f 73 75 70 65 72 66 69 73 68 2f 6a 73 2f 73 75 70 65 72 73 75 62 73 2e 70 68 70 } ///scripts/superfish/js/supersubs.php  01 00 
		$a_80_3 = {32 31 32 2e 34 37 2e 32 35 34 2e 31 38 37 } //212.47.254.187  01 00 
		$a_80_4 = {25 73 5c 49 4e 53 54 52 55 43 54 49 4f 4e 5f 46 4f 52 5f 48 45 4c 50 49 4e 47 5f 46 49 4c 45 5f 52 45 43 4f 56 45 52 59 2e 54 58 54 } //%s\INSTRUCTION_FOR_HELPING_FILE_RECOVERY.TXT  01 00 
		$a_80_5 = {25 73 25 30 38 58 25 30 38 58 25 30 38 58 25 30 38 58 2e } //%s%08X%08X%08X%08X.  01 00 
		$a_80_6 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //bcdedit /set {default} recoveryenabled No  05 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Pryncimoklyn_A__2{
	meta:
		description = "Ransom:Win32/Pryncimoklyn.A!!Pryncimoklyn.A!rsm,SIGNATURE_TYPE_ARHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {5f 00 48 00 45 00 4c 00 50 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 54 00 58 00 54 00 } //64 00  _HELP_INSTRUCTION.TXT
		$a_01_1 = {25 00 73 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 2e 00 4d 00 4f 00 4c 00 45 00 30 00 32 00 } //64 00  %s%08X%08X%08X%08X.MOLE02
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //64 00  vssadmin.exe Delete Shadows /All /Quiet
		$a_01_3 = {21 00 21 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2d 00 49 00 44 00 3a 00 20 00 25 00 73 00 20 00 21 00 21 00 21 00 } //05 00  !!! Your DECRYPT-ID: %s !!!
	condition:
		any of ($a_*)
 
}