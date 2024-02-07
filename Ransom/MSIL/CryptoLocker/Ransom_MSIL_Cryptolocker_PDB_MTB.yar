
rule Ransom_MSIL_Cryptolocker_PDB_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  have been encrypted
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_2 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //01 00  RECOVER__FILES
		$a_81_3 = {2e 6a 63 72 79 70 74 } //00 00  .jcrypt
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDB_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 61 76 65 20 66 75 6e 20 65 78 70 6c 6f 72 69 6e 67 20 79 6f 75 72 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 73 } //01 00  Have fun exploring your corrupted files
		$a_81_1 = {4b 65 79 20 69 73 20 64 65 73 74 72 6f 79 65 64 } //01 00  Key is destroyed
		$a_81_2 = {44 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 } //01 00  Decrypting files
		$a_81_3 = {43 72 61 70 73 6f 6d 77 61 72 65 } //00 00  Crapsomware
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDB_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {58 31 4a 6c 59 32 39 32 5a 58 4a 66 53 57 35 7a 64 48 4a 31 59 33 52 70 62 32 35 7a 4c 6e 52 34 64 41 } //01 00  X1JlY292ZXJfSW5zdHJ1Y3Rpb25zLnR4dA
		$a_81_1 = {58 31 4a 6c 59 32 39 32 5a 58 4a 66 53 57 35 7a 64 48 4a 31 59 33 52 70 62 32 35 7a 4c 6e 42 75 5a 77 } //01 00  X1JlY292ZXJfSW5zdHJ1Y3Rpb25zLnBuZw
		$a_81_2 = {53 57 35 6d 61 57 35 70 64 48 6c 4d 62 32 4e 72 } //01 00  SW5maW5pdHlMb2Nr
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}