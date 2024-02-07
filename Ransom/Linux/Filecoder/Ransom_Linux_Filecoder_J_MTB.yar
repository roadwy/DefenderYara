
rule Ransom_Linux_Filecoder_J_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 64 6f 6d 77 61 72 65 20 62 79 20 5b 61 66 6a 6f 73 65 70 68 5d } //01 00  Randomware by [afjoseph]
		$a_00_1 = {72 61 6e 64 6f 6d 77 61 72 65 } //01 00  randomware
		$a_00_2 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } //00 00  encrypt_file
	condition:
		any of ($a_*)
 
}