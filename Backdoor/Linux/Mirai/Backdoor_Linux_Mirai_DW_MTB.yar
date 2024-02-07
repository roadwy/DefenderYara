
rule Backdoor_Linux_Mirai_DW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5 } //0a 00 
		$a_00_1 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08 } //01 00 
		$a_00_2 = {6b 75 63 6b 2e 74 65 63 68 } //01 00  kuck.tech
		$a_00_3 = {54 43 50 20 43 6f 6e 6e 65 63 74 } //01 00  TCP Connect
		$a_00_4 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } //00 00  TSource Engine Query
	condition:
		any of ($a_*)
 
}