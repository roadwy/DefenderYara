
rule Trojan_Win64_AVTamper_B{
	meta:
		description = "Trojan:Win64/AVTamper.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_81_0 = {5b 2d 5d 20 53 74 6f 70 44 65 66 65 6e 64 65 72 53 65 72 76 69 63 65 73 20 45 72 72 6f 72 3a 20 25 69 } //01 00  [-] StopDefenderServices Error: %i
		$a_81_1 = {5b 2d 5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 4c 6f 67 67 65 64 4f 6e 55 73 65 72 28 29 20 45 72 72 6f 72 3a 20 25 69 } //01 00  [-] ImpersonatedLoggedOnUser() Error: %i
		$a_81_2 = {5b 2d 5d 20 57 49 4e 4c 4f 47 4f 4e 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 4c 6f 67 67 65 64 4f 6e 55 73 65 72 28 29 20 52 65 74 75 72 6e 20 43 6f 64 65 3a 20 25 69 } //02 00  [-] WINLOGON ImpersonatedLoggedOnUser() Return Code: %i
		$a_81_3 = {5b 2b 5d 20 54 52 55 53 54 45 44 49 4e 53 54 41 4c 4c 45 52 20 53 74 6f 70 44 65 66 65 6e 64 65 72 53 65 72 76 69 63 65 28 29 20 73 75 63 63 65 73 73 21 } //02 00  [+] TRUSTEDINSTALLER StopDefenderService() success!
		$a_81_4 = {5b 2d 5d 20 53 74 6f 70 44 65 66 65 6e 64 65 72 53 65 72 76 69 63 65 73 28 29 20 45 72 72 6f 72 3a 20 25 69 } //01 00  [-] StopDefenderServices() Error: %i
		$a_81_5 = {5b 2d 5d 20 25 73 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 4c 6f 67 67 65 64 4f 6e 55 73 65 72 28 29 20 52 65 74 75 72 6e 20 43 6f 64 65 3a 20 25 69 } //00 00  [-] %s ImpersonatedLoggedOnUser() Return Code: %i
	condition:
		any of ($a_*)
 
}