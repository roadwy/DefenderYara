
rule Ransom_Linux_Filecoder_G_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {21 5f 52 45 4e 4e 45 52 5f 52 45 41 44 4d 45 5f 21 2e 74 78 74 } //02 00 
		$a_00_1 = {67 5f 52 61 6e 73 6f 6d 48 65 61 64 65 72 } //01 00 
		$a_00_2 = {65 6e 63 72 79 70 74 5f 77 6f 72 6b 65 72 } //01 00 
		$a_00_3 = {2e 72 33 6e 6e 33 72 } //01 00 
		$a_00_4 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 2e } //01 00 
		$a_00_5 = {47 65 74 52 61 6e 73 6f 6d 43 6f 6e 66 69 67 } //00 00 
		$a_00_6 = {5d 04 00 00 } //e3 a6 
	condition:
		any of ($a_*)
 
}