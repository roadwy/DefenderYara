
rule Backdoor_WinNT_Farfli_F_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.F!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 c7 45 ee 73 00 66 c7 45 f0 25 00 66 c7 45 f2 73 00 90 02 1f 83 c4 14 83 7d 08 01 75 90 00 } //01 00 
		$a_03_1 = {8d 45 f8 50 6a 00 6a 00 c7 45 f8 00 1f 0a fa ff 15 90 01 02 01 00 6a 01 e8 90 01 04 6a 01 ff 15 90 01 02 01 00 c9 90 00 } //01 00 
		$a_03_2 = {38 5d 10 56 57 0f 84 90 01 02 00 00 83 7d 0c 14 0f 82 90 01 02 00 00 8d 45 10 89 5d 10 50 ff 75 0c ff 15 90 01 02 01 00 85 c0 0f 8c 90 01 02 00 00 33 c0 8d 7d f1 88 5d f0 8b 4d 10 ab ab ab 66 ab 90 00 } //01 00 
		$a_01_3 = {5a 00 77 00 45 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 65 00 4b 00 65 00 79 00 00 00 5a 00 77 00 43 00 6c 00 6f 00 73 00 65 00 00 00 5a 00 77 } //01 00 
		$a_01_4 = {50 73 53 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //00 00  PsSetCreateProcessNotifyRoutine
	condition:
		any of ($a_*)
 
}