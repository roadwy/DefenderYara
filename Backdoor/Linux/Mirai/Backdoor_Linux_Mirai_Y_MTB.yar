
rule Backdoor_Linux_Mirai_Y_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Y!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 20 a0 e1 8e 00 00 eb 00 30 a0 e1 00 00 53 e3 02 00 00 ca 01 30 a0 e3 30 34 0b e5 0d 00 00 ea 41 3e 4b e2 0c 30 43 e2 0c 30 43 e2 18 00 1b e5 03 10 a0 e1 10 20 a0 e3 17 02 00 eb 00 30 a0 e1 00 00 53 e3 02 00 00 aa 01 10 a0 e3 30 14 0b e5 } //01 00 
		$a_03_1 = {04 d0 4d e2 00 40 e0 e3 90 01 01 02 9f e5 90 01 01 45 8d e5 01 40 a0 e1 90 01 01 ff ff eb 90 01 02 8d e2 90 01 01 a0 8a e2 00 10 a0 e1 0a 00 a0 e1 90 01 02 00 eb 04 30 94 e5 00 00 53 e3 90 01 01 12 9f e5 0a 00 a0 e1 03 10 a0 11 90 01 02 00 eb 90 00 } //01 00 
		$a_03_2 = {03 10 a0 e1 c8 30 9f e5 91 23 83 e0 23 33 a0 e1 b4 30 0b e5 b4 30 1b e5 03 21 a0 e1 82 31 a0 e1 03 30 62 e0 b4 20 1b e5 02 30 83 e0 03 31 a0 e1 01 10 63 e0 b4 10 0b e5 b4 30 1b e5 23 21 a0 e1 90 01 02 9f e5 02 c1 93 e7 94 30 4b e2 03 00 a0 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}