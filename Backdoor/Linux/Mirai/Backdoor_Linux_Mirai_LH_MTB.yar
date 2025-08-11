
rule Backdoor_Linux_Mirai_LH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 5f 74 63 70 5f 66 6c 6f 6f 64 } //1 ddos_tcp_flood
		$a_01_1 = {63 6f 6e 6e 2e 6d 61 67 69 63 70 61 63 6b 65 74 6c 65 61 73 65 2e 6f 72 67 } //1 conn.magicpacketlease.org
		$a_01_2 = {64 64 6f 73 5f 75 64 70 5f 62 79 70 61 73 73 5f 66 6c 6f 6f 64 } //1 ddos_udp_bypass_flood
		$a_01_3 = {68 61 72 74 62 65 61 74 5f 73 65 6e 64 5f 73 68 75 74 64 6f 77 6e } //1 hartbeat_send_shutdown
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}