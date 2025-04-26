
rule Ransom_Linux_GonnaCry_A_MTB{
	meta:
		description = "Ransom:Linux/GonnaCry.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 70 20 62 72 6f 74 68 65 72 2c 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 62 65 6c 6f 77 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2c 20 63 68 65 65 72 73 21 } //2 Sup brother, all your files below have been encrypted, cheers!
		$a_00_1 = {4b 45 59 20 3d 20 25 73 20 49 56 20 3d 20 25 73 20 50 41 54 48 20 3d 20 25 73 } //1 KEY = %s IV = %s PATH = %s
		$a_00_2 = {2f 68 6f 6d 65 2f 74 61 72 63 69 73 69 6f 2f 74 65 73 74 73 2f } //1 /home/tarcisio/tests/
		$a_00_3 = {7a 69 70 20 62 61 63 6b 75 70 } //1 zip backup
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}