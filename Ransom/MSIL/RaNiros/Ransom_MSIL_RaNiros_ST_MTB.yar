
rule Ransom_MSIL_RaNiros_ST_MTB{
	meta:
		description = "Ransom:MSIL/RaNiros.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 41 45 53 20 32 35 36 20 61 6c 67 6f 72 69 74 6d 2e 20 4e 6f 20 6f 6e 65 20 63 61 6e 20 68 65 6c 70 20 79 6f 75 20 74 6f 20 72 65 73 74 6f 72 65 } //1 All you important files are encrypted with AES 256 algoritm. No one can help you to restore
		$a_81_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 73 6f 6d 65 20 79 6f 75 72 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 77 72 69 74 65 20 74 6f 20 65 6d 61 69 6c 20 61 6e 64 20 61 74 74 61 63 68 20 32 2d 33 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 If you want to restore some your files for free write to email and attach 2-3 encrypted files
		$a_81_2 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 74 6f 20 64 65 63 72 79 70 74 20 6f 74 68 65 72 20 66 69 6c 65 73 2e } //1 You have to pay to decrypt other files.
		$a_81_3 = {41 73 20 73 6f 6f 6e 20 61 73 20 77 65 20 67 65 74 20 62 69 74 63 6f 69 6e 73 20 79 6f 75 27 6c 6c 20 67 65 74 20 61 6c 6c 20 79 6f 75 72 20 64 65 63 72 79 70 74 65 64 20 64 61 74 61 20 62 61 63 6b } //1 As soon as we get bitcoins you'll get all your decrypted data back
		$a_81_4 = {44 6f 20 6e 6f 74 20 74 72 79 20 64 65 63 72 79 70 74 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 Do not try decrypt encrypted files
		$a_81_5 = {42 75 74 20 61 66 74 65 72 20 33 20 68 6f 75 72 73 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 2e } //1 But after 3 hours all your files will be deleted.
		$a_81_6 = {2f 66 20 2f 69 6d 20 4e 69 72 6f 73 2e 65 78 65 } //1 /f /im Niros.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}