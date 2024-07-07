
rule Ransom_Win64_SolasoCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/SolasoCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 5f 5f 52 45 41 44 2e 74 78 74 } //3 \__READ.txt
		$a_01_1 = {5c 5f 5f 52 45 41 44 5f 4d 45 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 59 4f 55 52 5f 46 49 4c 45 53 2e 74 78 74 } //3 \__READ_ME_TO_RECOVER_YOUR_FILES.txt
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 44 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 } //1 cmd.exe /C Del /f /q "%s
		$a_01_3 = {65 78 65 7c 6d 73 69 7c 64 6f 63 7c 64 6f 63 78 7c 78 6c 73 7c 78 6c 73 78 7c 78 6c 73 6d 7c 70 70 74 7c 70 64 66 7c 6a 70 67 7c 6a 70 65 67 7c 70 6e 67 7c 72 61 72 } //1 exe|msi|doc|docx|xls|xlsx|xlsm|ppt|pdf|jpg|jpeg|png|rar
		$a_01_4 = {2e 73 6f 6c 61 73 6f } //1 .solaso
		$a_03_5 = {5c 45 4e 43 52 49 50 54 41 52 5c 90 02 04 5c 90 02 10 5c 45 4e 43 52 49 50 54 41 52 2e 70 64 62 90 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=7
 
}