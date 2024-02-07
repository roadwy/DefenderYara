
rule Ransom_MSIL_NotherCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/NotherCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2e 00 74 00 6f 00 2f 00 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 70 00 68 00 70 00 } //01 00  .onion.to/readme.php
		$a_01_1 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  READ_ME.html
		$a_01_2 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2e 00 74 00 6f 00 2f 00 64 00 61 00 74 00 61 00 2e 00 70 00 68 00 70 00 } //01 00  .onion.to/data.php
		$a_01_3 = {5c 4e 4f 54 48 45 52 53 50 41 43 45 5f 55 53 45 2e 70 64 62 } //00 00  \NOTHERSPACE_USE.pdb
	condition:
		any of ($a_*)
 
}