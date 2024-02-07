
rule Ransom_MSIL_DesuCryptor_DA_MTB{
	meta:
		description = "Ransom:MSIL/DesuCryptor.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 74 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your system is not encrypted
		$a_81_1 = {64 65 63 72 79 70 74 } //01 00  decrypt
		$a_81_2 = {64 65 73 75 5f 63 72 79 70 74 6f 72 } //01 00  desu_cryptor
		$a_81_3 = {2e 64 65 73 75 } //01 00  .desu
		$a_81_4 = {6d 65 6d 65 2e 6a 70 65 67 } //00 00  meme.jpeg
	condition:
		any of ($a_*)
 
}