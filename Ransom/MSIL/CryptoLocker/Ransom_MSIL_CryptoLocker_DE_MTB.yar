
rule Ransom_MSIL_CryptoLocker_DE_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 4c 6f 63 6b 65 72 } //01 00  CryptoLocker
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 } //01 00  Encrypted
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //01 00  .locked
		$a_81_3 = {46 69 6c 65 73 20 44 65 63 72 79 70 74 65 64 } //00 00  Files Decrypted
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_CryptoLocker_DE_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files (count: n) have been encrypted
		$a_81_1 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 5f 5f 2e 6c 6f 63 6b 65 64 2e 74 78 74 } //01 00  RECOVER__FILES__.locked.txt
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_3 = {42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //00 00  BitcoinAddress
	condition:
		any of ($a_*)
 
}