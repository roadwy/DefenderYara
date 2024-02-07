
rule Ransom_Win32_Uzanticrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/Uzanticrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //01 00  DisableTaskMgr
		$a_01_1 = {48 00 4f 00 57 00 5f 00 54 00 4f 00 5f 00 44 00 45 00 43 00 59 00 50 00 48 00 45 00 52 00 5f 00 46 00 49 00 4c 00 45 00 53 00 } //01 00  HOW_TO_DECYPHER_FILES
		$a_01_2 = {44 00 72 00 6f 00 70 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 20 00 66 00 6f 00 72 00 20 00 74 00 65 00 73 00 74 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 70 00 72 00 6f 00 6f 00 66 00 } //01 00  Drop Encrypted file for test decryption proof
		$a_81_3 = {2e 55 5a 41 4e 54 49 43 52 59 50 54 } //00 00  .UZANTICRYPT
	condition:
		any of ($a_*)
 
}