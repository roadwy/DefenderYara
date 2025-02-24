
rule Backdoor_Linux_Mirai_KO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 5f 74 63 70 5f 73 74 6f 6d 70 } //1 attack_tcp_stomp
		$a_01_1 = {6b 69 6c 6c 5f 61 74 74 61 63 6b } //1 kill_attack
		$a_01_2 = {61 74 74 61 63 6b 5f 75 64 70 5f 61 6d 70 6c 69 66 69 63 61 74 69 6f 6e } //1 attack_udp_amplification
		$a_01_3 = {61 74 74 61 63 6b 5f 72 65 61 64 } //1 attack_read
		$a_01_4 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73 5f 62 79 5f 69 6e 6f 64 65 } //1 kill_process_by_inode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}