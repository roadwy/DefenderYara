
rule Ransom_MSIL_GoosCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/GoosCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 77 6e 63 72 79 } //01 00  get_wncry
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 74 00 68 00 65 00 20 00 67 00 6f 00 6f 00 73 00 65 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 21 00 } //01 00  Your files have been encrypted by the goose ransomware!
		$a_01_2 = {5c 73 75 73 2e 70 64 62 } //00 00  \sus.pdb
	condition:
		any of ($a_*)
 
}