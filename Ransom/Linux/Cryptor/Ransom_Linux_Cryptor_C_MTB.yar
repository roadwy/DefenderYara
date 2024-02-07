
rule Ransom_Linux_Cryptor_C_MTB{
	meta:
		description = "Ransom:Linux/Cryptor.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 65 6e 63 72 79 70 74 65 64 } //02 00  .encrypted
		$a_02_1 = {2e 2f 72 65 61 64 6d 65 90 02 05 2e 63 72 79 70 74 6f 90 00 } //01 00 
		$a_00_2 = {2e 2f 69 6e 64 65 78 2e 63 72 79 70 74 6f } //01 00  ./index.crypto
		$a_00_3 = {53 74 61 72 74 20 65 6e 63 72 79 70 74 69 6e 67 } //00 00  Start encrypting
	condition:
		any of ($a_*)
 
}