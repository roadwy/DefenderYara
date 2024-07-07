
rule Ransom_Linux_Gonnacry_C_MTB{
	meta:
		description = "Ransom:Linux/Gonnacry.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 70 20 62 72 6f 74 68 65 72 2c 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 62 65 6c 6f 77 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //5 Sup brother, all your files below have been encrypted
		$a_01_1 = {47 6f 6e 6e 61 43 72 79 } //5 GonnaCry
		$a_01_2 = {4b 45 59 20 3d 20 25 73 20 49 56 20 3d 20 25 73 20 50 41 54 48 20 3d 20 25 73 } //1 KEY = %s IV = %s PATH = %s
		$a_01_3 = {7a 69 70 20 62 61 63 6b 75 70 } //1 zip backup
		$a_01_4 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 73 } //1 encrypt_files
		$a_01_5 = {65 78 66 69 6c 74 72 61 74 65 5f 64 61 74 61 } //1 exfiltrate_data
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}