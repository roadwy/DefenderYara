
rule Ransom_MSIL_FileCryptor_MAK_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 77 61 72 65 } //Ransomware  1
		$a_02_1 = {50 00 61 00 79 00 20 00 77 00 69 00 74 00 68 00 20 00 [0-10] 20 00 42 00 54 00 43 00 } //1
		$a_02_2 = {50 61 79 20 77 69 74 68 20 [0-10] 20 42 54 43 } //1
		$a_80_3 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 75 73 20 77 69 74 68 20 42 69 74 63 6f 69 6e } //You have to pay us with Bitcoin  1
		$a_80_4 = {49 66 20 79 6f 75 20 74 68 69 6e 6b 20 79 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 20 79 6f 75 72 73 65 6c 66 2c 20 73 6f 20 64 6f 20 69 74 } //If you think you can decrypt your files with yourself, so do it  1
		$a_80_5 = {65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 41 45 53 } //encrypted using AES  1
		$a_80_6 = {59 6f 75 72 20 46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //Your Files has been encrypted  1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}
rule Ransom_MSIL_FileCryptor_MAK_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //Your files have been locked  1
		$a_80_1 = {59 6f 75 72 20 66 69 6c 65 73 20 6d 61 79 20 6f 6e 6c 79 20 62 65 20 72 65 73 74 6f 72 65 64 20 62 79 20 65 6e 74 65 72 69 6e 67 20 74 68 65 20 63 6f 72 72 65 63 74 20 70 61 73 73 77 6f 72 64 } //Your files may only be restored by entering the correct password  1
		$a_02_2 = {41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 6c 00 65 00 61 00 6b 00 65 00 64 00 20 00 61 00 66 00 74 00 65 00 72 00 20 00 [0-05] 20 00 68 00 6f 00 75 00 72 00 73 00 } //1
		$a_02_3 = {41 6c 6c 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 65 61 6b 65 64 20 61 66 74 65 72 20 [0-05] 20 68 6f 75 72 73 } //1
		$a_80_4 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 52 6e 7a } //HKEY_CURRENT_USER\SOFTWARE\Rnz  1
		$a_80_5 = {52 65 73 74 6f 72 65 20 6d 79 20 66 69 6c 65 73 } //Restore my files  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}