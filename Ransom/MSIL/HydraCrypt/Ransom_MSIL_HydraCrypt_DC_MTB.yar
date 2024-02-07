
rule Ransom_MSIL_HydraCrypt_DC_MTB{
	meta:
		description = "Ransom:MSIL/HydraCrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 6f 6c 64 65 72 54 6f 45 6e 63 72 79 70 74 } //01 00  FolderToEncrypt
		$a_81_1 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } //01 00  EncryptFiles
		$a_81_2 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_81_3 = {46 75 63 6b 65 64 } //00 00  Fucked
	condition:
		any of ($a_*)
 
}