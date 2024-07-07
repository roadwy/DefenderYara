
rule Ransom_Linux_Filecoder_K_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 64 6f 6d 77 61 72 65 20 62 79 20 5b 61 66 6a 6f 73 65 70 68 5d } //2 Randomware by [afjoseph]
		$a_01_1 = {62 79 74 65 5f 74 6f 5f 78 6f 72 20 3d } //2 byte_to_xor =
		$a_01_2 = {6f 73 69 72 69 73 } //1 osiris
		$a_01_3 = {6b 65 79 20 69 73 3a } //1 key is:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}