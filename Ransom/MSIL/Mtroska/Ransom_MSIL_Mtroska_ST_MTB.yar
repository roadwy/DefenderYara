
rule Ransom_MSIL_Mtroska_ST_MTB{
	meta:
		description = "Ransom:MSIL/Mtroska.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 48 55 53 54 4f 4e 57 45 48 41 56 45 41 50 52 4f 42 4c 45 4d 40 4b 45 45 4d 41 49 4c 2e 4d 45 } //1 .HUSTONWEHAVEAPROBLEM@KEEMAIL.ME
		$a_81_1 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 45 4e 43 52 59 50 54 45 44 5f 46 49 4c 45 53 } //1 HOW_TO_RECOVER_ENCRYPTED_FILES
		$a_81_2 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c } //1 /C choice /C Y /N /D Y /T 3 & Del
		$a_81_3 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //1 checkip.dyndns.org
		$a_81_4 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 21 } //1 YOUR FILES ARE ENCRYPTED!
		$a_81_5 = {41 66 74 65 72 20 70 61 79 6d 65 6e 74 20 77 65 20 77 69 6c 6c 20 73 65 6e 64 20 79 6f 75 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 74 68 61 74 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2e } //1 After payment we will send you the decryption tool that will decrypt all your files.
		$a_81_6 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 64 61 74 61 20 75 73 69 6e 67 20 74 68 69 72 64 20 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 2c 20 69 74 20 6d 61 79 20 63 61 75 73 65 20 70 65 72 6d 61 6e 65 6e 74 20 64 61 74 61 20 6c 6f 73 73 2e } //1 Do not try to decrypt your data using third party software, it may cause permanent data loss.
		$a_81_7 = {41 74 74 65 6d 70 74 73 20 74 6f 20 73 65 6c 66 2d 64 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 74 68 65 20 6c 6f 73 73 20 6f 66 20 79 6f 75 72 20 64 61 74 61 } //1 Attempts to self-decrypting files will result in the loss of your data
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=6
 
}