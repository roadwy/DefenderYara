
rule Ransom_MSIL_Hibotibo_AA_MTB{
	meta:
		description = "Ransom:MSIL/Hibotibo.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 6e 64 20 64 6f 63 75 6d 65 6e 74 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 75 73 } //01 00  All your important files and documents have been encrypted by us
		$a_01_1 = {48 69 74 6f 62 69 74 6f } //01 00  Hitobito
		$a_01_2 = {77 69 6c 6c 69 6e 67 20 74 6f 20 70 61 79 20 66 6f 72 20 79 6f 75 72 20 66 69 6c 65 73 } //00 00  willing to pay for your files
	condition:
		any of ($a_*)
 
}