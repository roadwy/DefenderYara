
rule Ransom_Win32_ElbeeCrypt_MFP_MTB{
	meta:
		description = "Ransom:Win32/ElbeeCrypt.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {65 6c 62 65 65 63 72 79 70 74 2d 6b 65 79 } //1 elbeecrypt-key
		$a_81_1 = {44 45 43 52 59 50 54 5f 59 4f 55 52 5f 46 49 4c 45 53 } //1 DECRYPT_YOUR_FILES
		$a_81_2 = {45 4c 42 45 45 43 52 59 50 54 } //1 ELBEECRYPT
		$a_81_3 = {54 61 72 67 65 74 65 64 20 65 78 74 65 6e 73 69 6f 6e 73 3a } //1 Targeted extensions:
		$a_81_4 = {52 6f 6f 74 20 64 69 72 65 63 74 6f 72 69 65 73 } //1 Root directories
		$a_81_5 = {4b 65 79 20 66 69 6e 67 65 72 70 72 69 6e 74 } //1 Key fingerprint
		$a_81_6 = {79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 77 65 72 65 20 6c 6f 63 6b 65 64 } //1 your personal files were locked
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}