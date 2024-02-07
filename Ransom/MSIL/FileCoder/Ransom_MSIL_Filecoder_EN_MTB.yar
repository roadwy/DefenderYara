
rule Ransom_MSIL_Filecoder_EN_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 5f 4d 45 2e 68 74 6d 6c } //01 00  READ_ME.html
		$a_81_1 = {2e 6f 6e 69 6f 6e 2e 63 61 62 2f 64 61 74 61 2e 70 68 70 } //01 00  .onion.cab/data.php
		$a_81_2 = {4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 70 64 62 } //01 00  NOTHERSPACE_USE.pdb
		$a_81_3 = {4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  NOTHERSPACE_USE.Properties
		$a_81_4 = {4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 65 78 65 } //00 00  NOTHERSPACE_USE.exe
	condition:
		any of ($a_*)
 
}