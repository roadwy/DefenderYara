
rule Ransom_Linux_BlackCat_H_MTB{
	meta:
		description = "Ransom:Linux/BlackCat.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 83 3d 2f 45 3c 00 00 48 89 e5 74 1a 48 8b 05 cb 3f 3d 00 48 85 c0 74 0e 48 8d 3d 17 45 3c 00 49 89 c3 c9 41 ff e3 } //1
		$a_01_1 = {41 57 41 56 41 54 53 50 48 8b 4f 08 48 89 c8 48 29 f0 48 39 d0 0f 83 e3 00 00 00 48 01 d6 0f 82 e6 00 00 00 49 89 ff 48 8d 04 09 48 39 f0 48 0f 47 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}