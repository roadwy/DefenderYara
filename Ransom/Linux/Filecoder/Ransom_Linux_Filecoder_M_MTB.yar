
rule Ransom_Linux_Filecoder_M_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 72 6f 70 52 61 6e 73 6f 6d 4e 6f 74 65 } //01 00 
		$a_01_1 = {77 72 69 74 65 45 6e 63 72 79 70 74 65 64 44 61 74 61 } //01 00 
		$a_01_2 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //01 00 
		$a_01_3 = {65 6e 63 72 79 70 74 6f 72 2f 66 69 6c 65 44 65 74 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}