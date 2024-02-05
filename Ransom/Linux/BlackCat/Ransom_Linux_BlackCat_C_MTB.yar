
rule Ransom_Linux_BlackCat_C_MTB{
	meta:
		description = "Ransom:Linux/BlackCat.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 6e 61 6d 65 70 72 65 6c 6f 63 6b 6e 6f 74 65 } //01 00 
		$a_01_1 = {6b 69 6c 6c 2d 76 6d 2d 69 6e 63 6c 75 64 65 6b 69 6c 6c 2d 76 6d 2d 65 78 63 6c 75 64 65 } //01 00 
		$a_01_2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c } //01 00 
		$a_01_3 = {65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 2d 2d 66 6f 72 6d 61 74 2d 70 61 72 61 6d 3d 66 69 65 6c 64 73 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}