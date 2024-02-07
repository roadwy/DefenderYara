
rule Ransom_Linux_Monti_A_MTB{
	meta:
		description = "Ransom:Linux/Monti.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 4f 4e 54 49 20 73 74 72 61 69 6e } //01 00  MONTI strain
		$a_01_1 = {2d 2d 76 6d 6b 69 6c 6c } //01 00  --vmkill
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 43 6f 6e 74 65 6e 74 49 6e 66 6f } //01 00  EncryptedContentInfo
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //01 00  encryptedData
		$a_01_4 = {76 6d 2d 6c 69 73 74 } //05 00  vm-list
		$a_01_5 = {2e 6d 6f 6e 74 69 } //05 00  .monti
		$a_01_6 = {2e 70 75 75 75 6b } //00 00  .puuuk
	condition:
		any of ($a_*)
 
}