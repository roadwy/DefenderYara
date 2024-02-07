
rule Trojan_Linux_Reptile_A{
	meta:
		description = "Trojan:Linux/Reptile.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 75 73 74 6f 6d 5f 72 6f 6c 33 32 } //01 00  custom_rol32
		$a_01_1 = {64 6f 5f 65 6e 63 6f 64 65 } //01 00  do_encode
		$a_01_2 = {72 65 70 74 69 6c 65 5f 62 6c 6f 62 } //01 00  reptile_blob
		$a_03_3 = {4f ec c4 4e 90 02 04 89 90 02 03 c1 90 01 01 02 89 90 01 01 01 90 01 01 01 90 01 01 c1 90 01 01 02 01 90 01 01 29 90 01 01 89 90 01 01 90 03 01 01 8b 89 90 02 08 90 03 01 01 33 31 90 00 } //04 00 
		$a_03_4 = {2f 72 65 70 74 69 6c 65 2f 72 65 70 74 69 6c 65 5f 63 6d 64 90 01 01 66 69 6c 65 2d 74 61 6d 70 65 72 69 6e 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}