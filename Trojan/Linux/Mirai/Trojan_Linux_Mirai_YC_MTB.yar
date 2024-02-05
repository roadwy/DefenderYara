
rule Trojan_Linux_Mirai_YC_MTB{
	meta:
		description = "Trojan:Linux/Mirai.YC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6e 63 2e 64 65 76 69 6c 73 64 65 6e 2e 6e 65 74 2f 38 55 73 41 2e 73 68 } //01 00 
		$a_00_1 = {77 61 6e 69 6e 66 3d 31 5f 49 4e 54 45 52 4e 45 54 5f 52 5f 56 49 44 } //01 00 
		$a_01_2 = {2f 74 6d 70 2f 6a 6e 6f } //01 00 
		$a_00_3 = {62 6f 61 66 6f 72 6d 2f 61 64 6d 69 6e 2f 66 6f 72 6d 50 69 6e 67 } //01 00 
		$a_00_4 = {34 36 2e 31 30 31 2e 31 35 37 2e 39 30 2f 36 36 36 2e 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}