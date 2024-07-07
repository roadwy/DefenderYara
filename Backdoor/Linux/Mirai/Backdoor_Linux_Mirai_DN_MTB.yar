
rule Backdoor_Linux_Mirai_DN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08 } //1
		$a_00_1 = {83 c4 10 85 ff 74 19 31 c0 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a4 01 00 00 } //1
		$a_00_2 = {2f 64 65 76 2f 6e 75 6c 6c } //1 /dev/null
		$a_00_3 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } //1 TSource Engine Query
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Backdoor_Linux_Mirai_DN_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.DN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {72 69 70 70 65 72 5f 6d 61 6b 65 5f 74 63 70 5f 70 6b 74 } //1 ripper_make_tcp_pkt
		$a_00_1 = {72 69 70 70 65 72 5f 6d 61 6b 65 5f 69 63 6d 70 5f 70 6b 74 } //1 ripper_make_icmp_pkt
		$a_00_2 = {72 69 70 70 65 72 5f 72 61 6e 64 } //1 ripper_rand
		$a_00_3 = {72 69 70 70 65 72 5f 72 61 6e 64 73 74 72 } //1 ripper_randstr
		$a_00_4 = {72 69 70 70 65 72 5f 70 61 72 73 65 62 75 66 } //1 ripper_parsebuf
		$a_00_5 = {63 6e 63 70 61 63 6b 65 74 5f 64 65 73 74 72 6f 79 5f 72 65 63 76 5f 64 61 74 61 } //1 cncpacket_destroy_recv_data
		$a_00_6 = {63 6e 63 70 61 63 6b 65 74 5f 63 72 65 61 74 65 5f 72 65 63 76 5f 64 61 74 61 } //1 cncpacket_create_recv_data
		$a_00_7 = {6b 6f 6d 6d 69 74 5f 73 75 69 6b 69 64 65 } //1 kommit_suikide
		$a_00_8 = {6c 6f 63 6b 65 72 5f 73 65 74 5f 6d 6f 64 65 } //1 locker_set_mode
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}