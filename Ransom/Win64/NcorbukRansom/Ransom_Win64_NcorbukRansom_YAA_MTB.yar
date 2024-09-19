
rule Ransom_Win64_NcorbukRansom_YAA_MTB{
	meta:
		description = "Ransom:Win64/NcorbukRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 6b 74 6f 70 2f 45 4d 41 49 4c 5f 4d 45 2e 74 78 74 } //1 Desktop/EMAIL_ME.txt
		$a_01_1 = {52 61 6e 73 6f 6d 57 61 72 65 2e 65 6e 63 72 79 70 74 5f 66 65 72 6e 65 74 5f 6b 65 79 } //1 RansomWare.encrypt_fernet_key
		$a_01_2 = {63 68 61 6e 67 65 5f 64 65 73 6b 74 6f 70 5f 62 61 63 6b 67 72 6f 75 6e 64 } //1 change_desktop_background
		$a_01_3 = {52 41 4e 53 4f 4d 5f 4e 4f 54 45 2e 74 78 74 } //1 RANSOM_NOTE.txt
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 6e 20 4d 69 6c 69 74 61 72 79 } //1 encrypted with an Military
		$a_01_5 = {61 64 64 72 65 73 73 20 66 6f 72 20 70 61 79 6d 65 6e 74 } //1 address for payment
		$a_01_6 = {74 6f 20 64 65 63 72 79 70 74 20 61 6c 6c 20 66 69 6c 65 73 } //1 to decrypt all files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}