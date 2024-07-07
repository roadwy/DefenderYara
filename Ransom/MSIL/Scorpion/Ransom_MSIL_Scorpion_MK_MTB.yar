
rule Ransom_MSIL_Scorpion_MK_MTB{
	meta:
		description = "Ransom:MSIL/Scorpion.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 63 6f 72 70 69 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 } //Scorpion Ransomware  1
		$a_80_1 = {46 49 4c 45 53 20 57 49 4c 4c 20 42 45 20 44 45 4c 45 54 45 44 20 49 4e 3a } //FILES WILL BE DELETED IN:  1
		$a_80_2 = {50 41 59 4d 45 4e 54 20 52 41 49 53 45 20 49 4e 3a } //PAYMENT RAISE IN:  1
		$a_80_3 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 4e 6f 77 20 46 75 6c 6c 79 20 44 65 6c 65 74 65 64 } //All Your Files Are Now Fully Deleted  1
		$a_80_4 = {4f 4f 50 53 20 59 4f 55 20 48 41 56 45 20 42 45 45 4e 20 49 4e 46 45 43 54 45 44 } //OOPS YOU HAVE BEEN INFECTED  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}