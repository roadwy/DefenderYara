
rule Ransom_Linux_Filecoder_K_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 61 6e 64 6f 6d 77 61 72 65 20 62 79 20 5b 61 66 6a 6f 73 65 70 68 5d } //02 00  Randomware by [afjoseph]
		$a_01_1 = {62 79 74 65 5f 74 6f 5f 78 6f 72 20 3d } //01 00  byte_to_xor =
		$a_01_2 = {6f 73 69 72 69 73 } //01 00  osiris
		$a_01_3 = {6b 65 79 20 69 73 3a } //00 00  key is:
	condition:
		any of ($a_*)
 
}