
rule Trojan_Win32_ClipBanker_D_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 31 35 2e 31 31 33 2e 39 33 } //01 00  http://185.215.113.93
		$a_01_1 = {65 00 67 00 65 00 67 00 65 00 37 00 65 00 67 00 37 00 67 00 37 00 67 00 35 00 37 00 35 00 68 00 37 00 65 00 67 00 37 00 68 00 37 00 67 00 } //01 00  egege7eg7g7g575h7eg7h7g
		$a_81_2 = {55 32 34 31 38 38 34 37 39 } //01 00  U24188479
		$a_81_3 = {45 32 37 34 34 30 37 34 36 } //01 00  E27440746
		$a_81_4 = {42 32 33 31 38 31 38 39 37 } //01 00  B23181897
		$a_81_5 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 } //01 00  bitcoincash:q
		$a_81_6 = {63 6f 73 6d 6f 73 31 } //00 00  cosmos1
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_D_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 77 74 75 } //01 00  SOFTWARE\wtu
		$a_81_1 = {6c 6c 73 64 6b 6a 33 65 30 70 72 } //01 00  llsdkj3e0pr
		$a_81_2 = {44 33 34 31 36 44 41 34 30 33 33 38 66 41 66 39 45 37 37 32 33 38 38 41 39 33 66 41 46 35 30 35 39 62 46 64 35 } //01 00  D3416DA40338fAf9E772388A93fAF5059bFd5
		$a_81_3 = {31 39 50 69 53 39 72 6a 75 76 69 57 61 64 6a 59 62 4d 37 6d 39 55 7a 45 73 7a 42 42 6a 69 69 64 65 6e } //01 00  19PiS9rjuviWadjYbM7m9UzEszBBjiiden
		$a_81_4 = {31 43 68 67 73 47 69 55 43 37 37 4b 69 62 31 6a 47 43 64 65 75 6e 70 74 6e 53 77 64 33 56 76 76 34 52 } //01 00  1ChgsGiUC77Kib1jGCdeunptnSwd3Vvv4R
		$a_81_5 = {31 44 66 6e 76 45 73 39 45 71 55 70 55 77 32 64 77 34 75 67 4a 68 4a 77 32 4b 66 55 37 63 4c 57 6e 59 } //00 00  1DfnvEs9EqUpUw2dw4ugJhJw2KfU7cLWnY
	condition:
		any of ($a_*)
 
}