
rule Trojan_BAT_AsyncRat_MD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a } //5
		$a_00_1 = {34 33 46 39 44 45 32 37 2d 41 34 33 30 2d 34 45 34 43 2d 38 38 37 39 2d 44 35 42 30 30 41 45 38 41 31 38 34 } //1 43F9DE27-A430-4E4C-8879-D5B00AE8A184
		$a_00_2 = {53 68 55 75 4a 50 51 45 59 4d 6f 46 58 51 6f 66 } //1 ShUuJPQEYMoFXQof
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AsyncRat_MD_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_81_2 = {43 72 79 70 74 6f 67 72 61 70 68 79 } //1 Cryptography
		$a_81_3 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_81_4 = {51 72 74 71 78 78 61 73 65 67 63 79 78 7a 6b 66 } //1 Qrtqxxasegcyxzkf
		$a_81_5 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
		$a_81_6 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_81_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_8 = {53 6c 65 65 70 } //1 Sleep
		$a_81_9 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}