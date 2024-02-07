
rule Backdoor_MacOS_Proton_E_MTB{
	meta:
		description = "Backdoor:MacOS/Proton.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {75 6e 7a 69 70 20 2d 6f 20 2f 74 6d 70 2f 25 40 20 26 26 20 6f 70 65 6e 20 2f 74 6d 70 2f 25 40 2e 61 70 70 90 02 04 63 68 6d 6f 64 20 2b 78 20 2f 74 6d 70 2f 90 00 } //01 00 
		$a_02_1 = {70 79 74 68 6f 6e 20 25 40 2f 90 02 04 2e 70 79 90 00 } //01 00 
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 47 6f 6f 67 6c 65 2f 43 68 72 6f 6d 65 2f 25 40 2f 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  /Library/Application Support/Google/Chrome/%@/Login Data
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 42 69 74 63 6f 69 6e 2f 77 61 6c 6c 65 74 2e 64 61 74 } //01 00  /Library/Application Support/Bitcoin/wallet.dat
		$a_00_4 = {72 65 6d 6f 74 65 5f 65 78 65 63 75 74 65 } //01 00  remote_execute
		$a_00_5 = {66 6f 72 63 65 5f 75 70 64 61 74 65 } //00 00  force_update
		$a_00_6 = {5d 04 00 00 } //ab b8 
	condition:
		any of ($a_*)
 
}