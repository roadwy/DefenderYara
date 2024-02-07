
rule Ransom_MSIL_Locky_DSA_MTB{
	meta:
		description = "Ransom:MSIL/Locky.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 2d 72 65 63 6f 76 65 72 79 2d 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 68 74 6d 6c } //01 00  file-recovery-instructions.html
		$a_81_1 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 20 42 79 20 5a 65 72 6f 2d 64 61 79 20 56 69 72 75 73 } //01 00  Your Files Have Been Encrypted By Zero-day Virus
		$a_81_2 = {54 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 74 6f 20 70 61 79 20 2e 31 20 42 69 74 63 6f 69 6e 73 } //01 00  The only way to recover your files is to pay .1 Bitcoins
		$a_81_3 = {46 6f 72 20 48 65 6c 70 20 65 6d 61 69 6c 3a 20 68 65 6c 70 40 7a 65 72 6f 64 61 79 73 61 6d 70 6c 65 32 30 31 38 2e 6e 65 74 } //01 00  For Help email: help@zerodaysample2018.net
		$a_81_4 = {42 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 3a 20 31 42 76 42 4d 53 45 59 73 74 57 65 74 71 54 46 6e 35 41 75 34 6d 34 47 46 67 37 78 4a 61 4e 56 4e 32 } //01 00  Bitcoin wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
		$a_81_5 = {57 45 20 41 50 4f 4c 4f 47 49 5a 45 20 42 55 54 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //00 00  WE APOLOGIZE BUT YOUR FILES HAVE BEEN ENCRYPTED
	condition:
		any of ($a_*)
 
}