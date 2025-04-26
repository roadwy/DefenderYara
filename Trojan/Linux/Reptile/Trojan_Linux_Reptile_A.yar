
rule Trojan_Linux_Reptile_A{
	meta:
		description = "Trojan:Linux/Reptile.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 75 73 74 6f 6d 5f 72 6f 6c 33 32 } //1 custom_rol32
		$a_01_1 = {64 6f 5f 65 6e 63 6f 64 65 } //1 do_encode
		$a_01_2 = {72 65 70 74 69 6c 65 5f 62 6c 6f 62 } //1 reptile_blob
		$a_03_3 = {4f ec c4 4e [0-04] 89 [0-03] c1 ?? 02 89 ?? 01 ?? 01 ?? c1 ?? 02 01 ?? 29 ?? 89 ?? (8b|89) [0-08] (|) 33 31 } //1
		$a_03_4 = {2f 72 65 70 74 69 6c 65 2f 72 65 70 74 69 6c 65 5f 63 6d 64 ?? 66 69 6c 65 2d 74 61 6d 70 65 72 69 6e 67 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*4) >=4
 
}