
rule Ransom_Win64_SolasoCrypt_MK_MTB{
	meta:
		description = "Ransom:Win64/SolasoCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 5f 4d 45 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 59 4f 55 52 5f 46 49 4c 45 53 2e 74 78 74 } //1 READ_ME_TO_RECOVER_YOUR_FILES.txt
		$a_81_1 = {79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 75 73 61 62 6c 65 } //1 your files were encrypted and are currently unusable
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 49 44 20 69 73 3a } //1 Your computer ID is:
		$a_03_3 = {65 6d 61 69 6c 3a [0-14] 40 62 75 78 6f 64 2e 63 6f 6d } //1
		$a_81_4 = {65 78 65 7c 6d 73 69 7c 64 6f 63 7c 64 6f 63 78 7c 78 6c 73 7c 78 6c 73 78 7c 78 6c 73 6d 7c 70 70 74 7c 70 64 66 7c 6a 70 67 7c 6a 70 65 67 7c 70 6e 67 7c 72 61 72 7c 37 7a 7c 7a 69 70 7c 62 64 66 } //1 exe|msi|doc|docx|xls|xlsx|xlsm|ppt|pdf|jpg|jpeg|png|rar|7z|zip|bdf
		$a_81_5 = {2e 73 6f 6c 61 73 6f } //1 .solaso
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}