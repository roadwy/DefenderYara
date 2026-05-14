
rule Ransom_Win32_Interlock_DA_MTB{
	meta:
		description = "Ransom:Win32/Interlock.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 20 73 70 65 63 69 66 69 65 64 20 64 69 72 65 63 74 6f 72 79 } //1 Encrypt specified directory
		$a_81_1 = {45 6e 63 72 79 70 74 20 73 70 65 63 69 66 69 65 64 20 66 69 6c 65 } //1 Encrypt specified file
		$a_81_2 = {44 65 6c 65 74 65 20 49 6e 74 65 72 6c 6f 63 6b 20 65 6e 63 72 79 70 74 6f 72 } //1 Delete Interlock encryptor
		$a_81_3 = {45 78 65 63 75 74 65 20 61 73 20 73 63 68 65 64 75 6c 65 64 20 74 61 73 6b } //1 Execute as scheduled task
		$a_81_4 = {52 65 6c 65 61 73 65 20 66 69 6c 65 73 20 75 73 69 6e 67 20 74 68 65 20 52 65 73 74 61 72 74 20 4d 61 6e 61 67 65 72 } //1 Release files using the Restart Manager
		$a_81_5 = {53 74 6f 72 65 73 20 65 6e 63 72 79 70 74 65 64 20 73 65 73 73 69 6f 6e 20 6b 65 79 73 } //1 Stores encrypted session keys
		$a_81_6 = {21 5f 4b 45 59 53 5f 46 4f 52 5f 44 45 43 52 59 50 54 5f 21 } //1 !_KEYS_FOR_DECRYPT_!
		$a_81_7 = {69 6e 73 69 64 65 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 inside the encrypted files
		$a_81_8 = {46 49 52 53 54 5f 52 45 41 44 5f 4d 45 2e 74 78 74 } //1 FIRST_READ_ME.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=5
 
}