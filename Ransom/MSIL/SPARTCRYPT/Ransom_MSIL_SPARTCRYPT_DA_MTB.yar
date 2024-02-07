
rule Ransom_MSIL_SPARTCRYPT_DA_MTB{
	meta:
		description = "Ransom:MSIL/SPARTCRYPT.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files have been encrypted
		$a_81_1 = {48 6f 77 5f 54 6f 5f 52 65 73 74 6f 72 65 5f 59 6f 75 72 5f 46 69 6c 65 73 } //01 00  How_To_Restore_Your_Files
		$a_81_2 = {2e 45 6e 63 72 79 70 74 65 64 } //01 00  .Encrypted
		$a_81_3 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 4c 69 73 74 } //00 00  EncryptedFilesList
	condition:
		any of ($a_*)
 
}