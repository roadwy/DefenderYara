
rule Ransom_Linux_Babuk_G_MTB{
	meta:
		description = "Ransom:Linux/Babuk.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files are encrypted
		$a_00_1 = {43 59 4c 41 4e 43 45 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 CYLANCE_README.txt
		$a_00_2 = {2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 } //1 /path/to/be/encrypted
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}