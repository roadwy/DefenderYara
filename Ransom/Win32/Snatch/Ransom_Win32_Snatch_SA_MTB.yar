
rule Ransom_Win32_Snatch_SA_MTB{
	meta:
		description = "Ransom:Win32/Snatch.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6e 79 20 61 74 74 65 6d 70 74 20 62 79 20 61 6e 79 20 70 65 72 73 6f 6e 20 74 6f 20 64 65 63 72 79 70 74 20 74 68 65 20 66 69 6c 65 73 20 6f 72 20 62 72 75 74 65 66 6f 72 63 65 20 74 68 65 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 66 75 74 69 6c 65 20 61 6e 64 20 6c 65 61 64 20 74 6f 20 6c 6f 73 73 20 6f 66 20 74 69 6d 65 20 61 6e 64 20 70 72 65 63 69 6f 75 73 20 64 61 74 61 } //01 00  Any attempt by any person to decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 41 45 53 20 32 35 36 20 6b 65 79 20 62 69 74 20 61 6c 67 6f 72 69 74 68 6d 20 61 6e 64 20 74 68 65 20 70 61 73 73 77 6f 72 64 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 34 30 39 36 20 62 69 74 20 52 53 41 20 70 75 62 6c 69 63 20 6b 65 79 } //01 00  Your files have been encrypted using AES 256 key bit algorithm and the password encrypted with a 4096 bit RSA public key
		$a_81_2 = {41 64 69 6f 73 20 4d 75 63 68 61 63 68 6f 7a 21 21 21 } //01 00  Adios Muchachoz!!!
		$a_81_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  -----BEGIN RSA PUBLIC KEY-----
		$a_81_4 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //00 00  Go build ID:
	condition:
		any of ($a_*)
 
}