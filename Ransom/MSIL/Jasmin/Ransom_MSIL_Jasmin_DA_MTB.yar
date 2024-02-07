
rule Ransom_MSIL_Jasmin_DA_MTB{
	meta:
		description = "Ransom:MSIL/Jasmin.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4a 61 73 6d 69 6e 20 45 6e 63 72 79 70 74 6f 72 } //01 00  Jasmin Encryptor
		$a_81_1 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00  unlock your files
		$a_81_2 = {2e 72 61 6e 73 69 6d 75 6c 61 74 6f 72 } //01 00  .ransimulator
		$a_81_3 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //00 00  bytesToBeEncrypted
	condition:
		any of ($a_*)
 
}