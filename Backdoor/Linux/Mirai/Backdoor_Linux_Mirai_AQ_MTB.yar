
rule Backdoor_Linux_Mirai_AQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 40 97 e5 00 00 54 e3 0c 90 01 02 0a 30 31 9f e5 03 30 96 e7 00 40 83 e5 2f 10 a0 e3 00 00 97 e5 e7 90 01 02 eb 1c 31 9f e5 00 00 50 e3 03 20 96 e7 01 30 80 12 00 00 82 e5 00 30 82 15 00 40 82 05 04 21 9f e5 04 31 9f e5 03 30 62 e0 90 00 } //01 00 
		$a_00_1 = {02 30 83 e0 4c 21 13 e5 1f 10 04 e2 52 21 a0 e1 01 00 12 e3 c6 ff ff 0a 0a 00 a0 e1 dc 0a 00 eb 0a 10 a0 e1 00 20 a0 e1 01 39 a0 e3 04 00 a0 e1 3d 0c 00 eb 58 45 9d e5 5c 75 8d e5 8f ff ff ea } //01 00 
		$a_03_2 = {03 00 95 e8 03 00 84 e8 90 01 02 00 eb b6 20 d7 e1 01 00 00 e2 18 30 8d e2 00 01 a0 e1 03 00 80 e0 22 34 a0 e1 ff 20 02 e2 02 24 83 e1 08 10 10 e5 01 39 a0 e3 08 00 a0 e1 90 01 01 0d 00 eb 00 00 a0 e3 90 01 01 01 00 eb 09 30 d7 e5 03 30 8a e0 03 00 50 e1 ea ff ff ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}