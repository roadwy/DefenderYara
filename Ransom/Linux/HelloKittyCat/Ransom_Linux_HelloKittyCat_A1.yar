
rule Ransom_Linux_HelloKittyCat_A1{
	meta:
		description = "Ransom:Linux/HelloKittyCat.A1,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 75 6e 73 68 69 6e 65 2f 6d 6f 76 65 6d 65 6e 74 } //sunshine/movement  1
		$a_80_1 = {53 74 61 72 74 45 6e 63 } //StartEnc  1
		$a_80_2 = {65 6e 63 72 79 70 74 65 72 } //encrypter  1
		$a_80_3 = {62 72 75 74 65 } //brute  1
		$a_80_4 = {53 53 48 2e } //SSH.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}