
rule Ransom_Win64_SnatchRansom_YAB_MTB{
	meta:
		description = "Ransom:Win64/SnatchRansom.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 56 44 4d 4f 70 65 72 61 74 69 6f 6e 53 74 61 72 74 65 64 } //01 00 
		$a_01_1 = {63 72 79 70 74 6f 2f 72 61 6e 64 2f 72 61 6e 64 2e 67 6f } //01 00 
		$a_01_2 = {6d 61 69 6e 2e 54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00 
		$a_01_4 = {48 8d 15 15 c4 29 00 89 04 8a 48 8d 41 01 48 3d 00 01 00 00 7d 0a 48 89 c1 c1 e0 18 31 d2 eb 04 c3 48 ff c2 48 83 fa 08 7d d6 0f ba e0 1f 73 09 d1 e0 35 b7 1d c1 04 eb e8 d1 e0 90 eb e3 } //00 00 
	condition:
		any of ($a_*)
 
}