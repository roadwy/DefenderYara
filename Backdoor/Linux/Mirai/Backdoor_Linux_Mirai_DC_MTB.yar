
rule Backdoor_Linux_Mirai_DC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 5f 74 63 70 2e 63 } //01 00  attack_tcp.c
		$a_01_1 = {63 68 61 63 68 61 32 30 5f 71 75 61 72 74 65 72 72 6f 75 6e 64 } //01 00  chacha20_quarterround
		$a_01_2 = {61 74 74 61 63 6b 5f 75 64 70 2e 63 } //01 00  attack_udp.c
		$a_01_3 = {6d 79 6c 6f 63 6b } //01 00  mylock
		$a_01_4 = {66 6c 6f 6f 64 5f 74 63 70 5f 61 63 6b } //00 00  flood_tcp_ack
	condition:
		any of ($a_*)
 
}