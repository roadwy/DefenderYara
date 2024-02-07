
rule Ransom_MSIL_Cry_DA_MTB{
	meta:
		description = "Ransom:MSIL/Cry.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 72 79 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Your files have been encrypted by CryRansomware
		$a_81_1 = {4e 65 76 65 72 20 6f 70 65 6e 20 72 61 6e 64 6f 6d 20 66 69 6c 65 73 } //01 00  Never open random files
		$a_81_2 = {63 72 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  cry.Properties.Resources
		$a_81_3 = {67 65 74 5f 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //00 00  get_EncryptionKey
	condition:
		any of ($a_*)
 
}