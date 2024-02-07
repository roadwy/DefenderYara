
rule Trojan_Win32_ButeRat_MA_MTB{
	meta:
		description = "Trojan:Win32/ButeRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 03 58 57 6a 02 50 57 57 68 00 00 00 c0 8d 90 01 04 ff 50 ff 15 90 00 } //01 00 
		$a_03_1 = {8d 45 fc 50 6a 01 6a 00 bb 90 01 04 53 68 01 00 00 80 ff d7 90 00 } //01 00 
		$a_01_2 = {49 6e 74 65 72 6e 65 74 53 65 74 50 65 72 53 69 74 65 43 6f 6f 6b 69 65 44 65 63 69 73 69 6f 6e 57 } //01 00  InternetSetPerSiteCookieDecisionW
		$a_01_3 = {5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //01 00  \INTERNAL\REMOTE.EXE
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}