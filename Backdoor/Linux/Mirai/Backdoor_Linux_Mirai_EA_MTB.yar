
rule Backdoor_Linux_Mirai_EA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 64 7a 62 6f 74 } //01 00  tedzbot
		$a_01_1 = {2f 76 61 72 2f 53 6f 66 69 61 } //01 00  /var/Sofia
		$a_01_2 = {2f 65 74 63 2f 69 6e 69 74 2e 64 2f 6e 6f 74 68 69 6e 67 } //01 00  /etc/init.d/nothing
		$a_01_3 = {00 50 a0 e3 7c c1 8e e5 05 1a 8d e2 05 2a 8d e2 51 cc 8d e2 80 51 8e e5 7c c0 8c e2 cc 10 81 e2 4c 20 82 e2 05 30 a0 e1 0a 00 a0 e1 00 c0 8d e5 49 fd ff eb 00 40 a0 e1 05 00 a0 e1 a6 fd ff eb 05 00 54 e1 44 00 8d e5 55 ff ff da 18 80 9d e5 34 50 8d e5 } //00 00 
	condition:
		any of ($a_*)
 
}