
rule Backdoor_MacOS_BlackHol_A_xp{
	meta:
		description = "Backdoor:MacOS/BlackHol.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 0c 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 90 02 08 2f 90 02 07 2f 61 64 64 2e 7a 69 70 90 00 } //02 00 
		$a_00_1 = {4b 65 79 6c 6f 67 67 65 72 2e 7a 69 70 } //01 00 
		$a_02_2 = {2e 69 73 69 67 68 74 63 61 70 74 75 72 65 2e 74 78 74 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 90 02 08 2f 90 02 07 2f 69 73 69 67 68 74 63 61 70 74 75 72 65 2e 74 78 74 90 00 } //01 00 
		$a_02_3 = {2e 4a 61 76 61 2f 44 61 74 61 2f 90 02 08 2f 69 73 69 67 68 74 63 61 70 74 75 72 65 20 2d 77 20 31 32 30 30 20 2d 68 20 38 30 30 20 2d 74 20 6a 70 67 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 2f 44 61 74 61 2f 63 61 70 74 75 72 65 30 31 2e 6a 70 67 90 00 } //01 00 
		$a_00_4 = {2f 2e 44 61 74 61 2f 61 64 64 32 2e 7a 69 70 } //01 00 
		$a_00_5 = {72 6d 20 2d 72 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 55 70 64 61 74 65 72 2f 2e 44 61 74 61 2f 2e 6b 69 6c 6c 2e 7a 69 70 } //03 00 
		$a_00_6 = {42 6c 61 63 6b 48 6f 6c 65 20 52 41 54 } //01 00 
		$a_02_7 = {54 61 6b 65 20 61 20 53 6e 61 70 73 68 6f 74 20 66 72 6f 6d 20 74 68 65 20 69 53 69 67 68 74 90 02 04 53 6c 6f 77 20 64 6f 77 6e 20 74 68 65 20 43 50 55 20 77 69 74 68 20 61 20 6c 6f 6f 70 20 66 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_00_8 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 73 74 6f 70 20 74 68 65 20 43 6f 64 65 20 6f 6e 20 74 68 65 20 56 69 63 74 69 6d 73 20 43 6f 6d 70 75 74 65 72 20 77 68 69 63 68 20 65 6e 61 62 6c 65 73 20 74 68 65 20 69 53 69 67 68 74 20 4c 61 6d 70 20 61 6e 64 20 74 68 65 20 4d 69 63 72 6f } //01 00 
		$a_00_9 = {41 70 70 6c 65 45 76 65 6e 74 52 65 63 6f 72 64 } //01 00 
		$a_00_10 = {4b 65 72 6e 65 6c 50 61 6e 69 6b 2e 20 53 79 73 74 65 6d 20 69 73 20 63 6f 72 72 75 70 74 2c 20 66 72 65 65 7a 69 6e 67 20 44 65 73 6b 74 6f 70 20 4e 4f 57 21 } //01 00 
		$a_00_11 = {52 65 6d 6f 74 65 41 64 64 72 65 73 73 2e 47 65 74 } //00 00 
		$a_00_12 = {5d 04 00 } //00 ef 
	condition:
		any of ($a_*)
 
}