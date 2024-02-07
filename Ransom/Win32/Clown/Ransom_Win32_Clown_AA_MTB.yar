
rule Ransom_Win32_Clown_AA_MTB{
	meta:
		description = "Ransom:Win32/Clown.AA!MTB,SIGNATURE_TYPE_PEHSTR,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 4c 4f 57 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } //05 00  CLOWN RANSOMWARE
		$a_01_1 = {41 6c 6c 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //05 00  All personal files on your computer are encrypted!
		$a_01_2 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 2e 74 78 74 } //05 00  HOW TO RECOVER ENCRYPTED FILES.txt
		$a_01_3 = {79 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 69 6e 20 42 69 74 63 6f 69 6e } //02 00  you have to pay in Bitcoin
		$a_01_4 = {41 64 6d 69 6e 45 6e 63 40 50 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //02 00  AdminEnc@Protonmail.com
		$a_01_5 = {44 65 63 72 79 70 74 41 64 6d 69 6e 40 70 72 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //00 00  DecryptAdmin@prtonmail.com
		$a_01_6 = {00 5d 04 00 00 58 2a 04 80 5c 37 00 } //00 59 
	condition:
		any of ($a_*)
 
}