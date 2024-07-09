
rule Backdoor_Linux_Mirai_M_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 35 71 36 68 65 33 64 62 72 73 67 6d 63 6c 6b 69 75 34 74 6f 31 38 6e 70 61 76 6a 37 30 32 66 } //1 w5q6he3dbrsgmclkiu4to18npavj702f
		$a_00_1 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //1 killer_kill_by_port
		$a_00_2 = {61 74 74 61 63 6b 5f 61 70 70 5f 68 74 74 70 } //1 attack_app_http
		$a_00_3 = {61 74 74 61 63 6b 5f 74 63 70 5f 73 74 6f 6d 70 } //1 attack_tcp_stomp
		$a_00_4 = {61 74 74 61 63 6b 5f 75 64 70 5f 70 6c 61 69 6e } //1 attack_udp_plain
		$a_00_5 = {61 74 74 61 63 6b 5f 75 64 70 5f 76 73 65 } //1 attack_udp_vse
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule Backdoor_Linux_Mirai_M_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 50 50 e2 12 00 00 0a 04 40 95 e5 ?? ff ff eb 00 10 d5 e5 ?? 06 00 eb ?? 31 94 e7 05 00 a0 e1 04 30 8d e5 ?? 01 00 eb 06 00 a0 e1 0d 10 a0 e1 10 20 a0 e3 ?? ?? ?? eb 01 00 70 e3 00 40 a0 e1 [0-09] 06 00 a0 e1 10 d0 8d e2 70 ?? bd e8 } //5
		$a_03_1 = {8f bc 00 10 24 03 ff ff 8f 99 81 40 10 ?? ?? ?? 02 40 20 21 02 40 10 21 8f bf 00 34 8f b2 00 30 8f b1 00 2c 8f b0 00 28 03 e0 00 08 27 bd 00 38 03 20 f8 09 24 12 ff ff 8f bc 00 10 10 ?? ?? ?? 02 40 10 21 03 ?? ?? ?? 24 12 ff ff 8f bc 00 10 } //5
		$a_00_2 = {62 6c 61 63 6b 2e 66 72 69 64 67 65 78 70 65 72 74 73 2e 63 63 } //1 black.fridgexperts.cc
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1) >=6
 
}