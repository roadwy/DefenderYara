
rule Backdoor_Linux_Mirai_Bv_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Bv!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {04 10 90 e5 03 30 96 e7 00 00 51 e3 00 50 93 e5 17 } //05 00 
		$a_00_1 = {e0 97 e7 04 20 16 e5 00 30 9e e5 03 c0 c2 e3 08 50 46 e2 03 00 5c e1 05 40 a0 e1 07 00 00 8a 03 30 83 e3 08 30 0e e4 ac 11 a0 e1 04 20 8e e2 01 31 92 e7 08 30 85 e5 01 } //01 00 
		$a_01_2 = {61 74 74 61 63 6b 5f 73 70 6f 6f 66 65 64 } //01 00  attack_spoofed
		$a_01_3 = {61 74 74 61 63 6b 5f 74 63 70 } //01 00  attack_tcp
		$a_00_4 = {65 78 70 6c 6f 69 74 65 72 2e 63 } //01 00  exploiter.c
		$a_01_5 = {41 74 74 61 63 6b 70 69 64 } //00 00  Attackpid
	condition:
		any of ($a_*)
 
}