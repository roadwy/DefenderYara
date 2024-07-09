
rule Ransom_MSIL_Mrynimal{
	meta:
		description = "Ransom:MSIL/Mrynimal,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 6f 74 61 75 72 2e 65 78 65 } //10 Minotaur.exe
		$a_81_1 = {20 6d 69 6e 6f 74 61 75 72 40 34 32 30 62 6c 61 7a 65 2e 69 74 } //10  minotaur@420blaze.it
		$a_81_2 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 20 42 59 20 28 4d 49 4e 4f 54 41 55 52 29 20 52 41 4e 53 4f 4d 57 41 52 45 21 } //10 ALL YOUR FILES ARE ENCRYPTED BY (MINOTAUR) RANSOMWARE!
		$a_81_3 = {46 4f 52 20 44 45 43 52 59 50 54 20 59 4f 55 52 20 46 49 4c 45 53 20 4e 45 45 44 20 54 4f 20 50 41 59 20 55 53 20 41 20 28 30 2e 31 32 35 20 42 54 43 29 21 } //5 FOR DECRYPT YOUR FILES NEED TO PAY US A (0.125 BTC)!
		$a_81_4 = {53 45 4e 44 20 59 4f 55 52 20 28 4b 45 59 29 20 54 4f 20 4f 55 52 20 45 2d 4d 41 49 4c 20 46 4f 52 20 53 55 50 50 4f 52 54 21 } //5 SEND YOUR (KEY) TO OUR E-MAIL FOR SUPPORT!
		$a_81_5 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 74 78 74 } //5 How To Decrypt Files.txt
		$a_03_6 = {50 72 69 76 61 74 65 5c 4d 69 6e 6f 74 61 75 72 5c 4d 69 6e 6f 74 61 75 72 [0-18] 5c 4d 69 6e 6f 74 61 75 72 2e 70 64 62 } //30
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5+(#a_03_6  & 1)*30) >=40
 
}