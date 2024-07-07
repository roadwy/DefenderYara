
rule Ransom_Linux_Babuk_M{
	meta:
		description = "Ransom:Linux/Babuk.M,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {42 75 6f 6e 67 69 6f 72 6e 6f 20 6c 61 20 6d 69 61 20 62 65 6c 6c 61 20 49 74 61 6c 69 61 } //Buongiorno la mia bella Italia  1
		$a_80_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 74 68 65 20 52 61 6e 73 6f 6d 48 6f 75 73 65 } //Welcome to the RansomHouse  1
		$a_80_2 = {59 6f 75 20 61 72 65 20 6c 6f 63 6b 65 64 20 62 79 } //You are locked by  1
		$a_80_3 = {57 20 48 20 49 20 54 20 45 20 20 52 20 41 20 42 20 42 20 49 20 54 } //W H I T E  R A B B I T  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}