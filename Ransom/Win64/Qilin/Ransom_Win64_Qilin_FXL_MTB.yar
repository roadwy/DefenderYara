
rule Ransom_Win64_Qilin_FXL_MTB{
	meta:
		description = "Ransom:Win64/Qilin.FXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //3 YOUR FILES HAVE BEEN ENCRYPTED
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 } //3 All your documents, photos, databases
		$a_81_2 = {61 6e 64 20 62 61 63 6b 75 70 73 20 68 61 76 65 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //1 and backups have been locked
		$a_81_3 = {46 69 6e 64 20 21 21 21 5f 52 45 41 44 5f 4d 45 5f 21 21 21 2e 74 78 74 20 6f 6e 20 79 6f 75 72 20 64 65 73 6b 74 6f 70 } //1 Find !!!_READ_ME_!!!.txt on your desktop
		$a_81_4 = {44 6f 20 4e 4f 54 20 64 65 6c 65 74 65 20 6f 72 20 6d 6f 64 69 66 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //2 Do NOT delete or modify encrypted files
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2) >=10
 
}