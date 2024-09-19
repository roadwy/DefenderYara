
rule Ransom_Win32_Lorenz_YAA_MTB{
	meta:
		description = "Ransom:Win32/Lorenz.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //5 ALL YOUR FILES ARE ENCRYPTED
		$a_01_1 = {72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 74 6f 20 67 65 74 20 61 20 64 65 63 72 79 70 74 6f 72 } //1 recover your files is to get a decryptor
		$a_01_2 = {54 6f 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 6f 72 } //1 To get the decryptor
		$a_01_3 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 66 69 6c 65 73 } //1 Do not rename files
		$a_01_4 = {44 6f 20 6e 6f 74 20 61 74 74 65 6d 70 74 20 74 6f 20 64 65 63 72 79 70 74 20 64 61 74 61 20 75 73 69 6e 67 20 74 68 69 72 64 20 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 } //1 Do not attempt to decrypt data using third party software
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}