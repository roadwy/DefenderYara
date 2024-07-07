
rule Ransom_MSIL_Makop_MAK_MTB{
	meta:
		description = "Ransom:MSIL/Makop.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6d 61 6b 6f 70 } //makop  1
		$a_80_1 = {45 6e 63 72 79 70 74 65 64 3a } //Encrypted:  1
		$a_80_2 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 63 72 79 70 74 3a } //Failed to encrypt:  1
		$a_80_3 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //your files have been encrypted  1
		$a_80_4 = {5c 52 45 41 44 4d 45 2d } //\README-  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}