
rule Ransom_MSIL_Exocrypt_DA_MTB{
	meta:
		description = "Ransom:MSIL/Exocrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 } //01 00  Your Personal Files Are Encrypted
		$a_81_1 = {45 78 6f 63 72 79 70 74 20 58 54 43 } //01 00  Exocrypt XTC
		$a_81_2 = {44 4f 5f 4e 4f 54 5f 44 45 4c 45 54 45 } //01 00  DO_NOT_DELETE
		$a_81_3 = {2e 78 74 63 } //00 00  .xtc
	condition:
		any of ($a_*)
 
}