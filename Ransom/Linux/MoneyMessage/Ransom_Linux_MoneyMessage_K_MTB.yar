
rule Ransom_Linux_MoneyMessage_K_MTB{
	meta:
		description = "Ransom:Linux/MoneyMessage.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 2d 2d 66 6f 72 6d 61 74 2d 70 61 72 61 6d 3d 66 69 65 6c 64 73 3d 3d } //01 00 
		$a_00_1 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d } //01 00 
		$a_00_2 = {76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 20 7c 20 61 77 6b 20 2d 46 20 } //01 00 
		$a_00_3 = {63 72 79 70 74 5f 6f 6e 6c 79 5f 74 68 65 73 65 5f 64 69 72 65 63 74 6f 72 69 65 73 } //01 00 
		$a_00_4 = {6d 6f 6e 65 79 70 75 6e 63 74 5f 62 79 6e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}