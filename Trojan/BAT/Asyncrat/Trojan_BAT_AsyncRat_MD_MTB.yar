
rule Trojan_BAT_AsyncRat_MD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_81_2 = {43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  Cryptography
		$a_81_3 = {43 69 70 68 65 72 4d 6f 64 65 } //01 00  CipherMode
		$a_81_4 = {51 72 74 71 78 78 61 73 65 67 63 79 78 7a 6b 66 } //01 00  Qrtqxxasegcyxzkf
		$a_81_5 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_81_6 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_81_7 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_8 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_9 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}