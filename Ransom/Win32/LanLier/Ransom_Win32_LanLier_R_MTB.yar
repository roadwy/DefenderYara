
rule Ransom_Win32_LanLier_R_MTB{
	meta:
		description = "Ransom:Win32/LanLier.R!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  all your files have been encrypted
		$a_01_1 = {42 65 66 6f 72 65 20 70 61 79 69 6e 67 20 79 6f 75 20 73 65 6e 64 20 75 73 20 75 70 20 74 6f 20 33 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 64 65 63 72 79 70 74 69 6f 6e } //01 00  Before paying you send us up to 3 files for free decryption
		$a_01_2 = {44 65 63 72 79 70 74 69 6f 6e 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 20 74 68 65 20 68 65 6c 70 20 6f 66 20 74 68 69 72 64 20 70 61 72 74 69 65 73 20 6d 61 79 20 63 61 75 73 65 20 69 6e 63 72 65 61 73 65 64 20 70 72 69 63 65 } //01 00  Decryption of your files with the help of third parties may cause increased price
		$a_01_3 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 2e 54 58 54 } //01 00  HOW TO RECOVER ENCRYPTED FILES.TXT
		$a_01_4 = {5b 42 41 43 4b 55 50 53 5d 5b 44 52 49 56 45 53 5d 5b 53 48 41 52 45 53 5d 5b 45 58 54 45 4e 53 49 4f 4e 5d } //00 00  [BACKUPS][DRIVES][SHARES][EXTENSION]
	condition:
		any of ($a_*)
 
}