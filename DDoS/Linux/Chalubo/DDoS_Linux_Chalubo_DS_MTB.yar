
rule DDoS_Linux_Chalubo_DS_MTB{
	meta:
		description = "DDoS:Linux/Chalubo.DS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f } //1
		$a_00_1 = {74 61 73 6b 5f 64 65 63 72 79 70 74 } //1 task_decrypt
		$a_00_2 = {2f 74 6d 70 2f 74 6d 70 6e 61 6d 5f 58 58 58 58 58 58 } //1 /tmp/tmpnam_XXXXXX
		$a_00_3 = {2f 74 6d 70 2f 74 6d 70 66 69 6c 65 5f 58 58 58 58 58 58 } //1 /tmp/tmpfile_XXXXXX
		$a_03_4 = {68 74 74 70 3a 2f 2f 90 02 15 3a 38 38 35 32 2f 90 02 08 2f 90 02 08 2e 64 61 74 90 00 } //1
		$a_00_5 = {61 74 74 61 63 6b 5f 64 6e 73 } //1 attack_dns
		$a_00_6 = {61 74 74 61 63 6b 5f 75 64 70 } //1 attack_udp
		$a_00_7 = {65 61 73 79 5f 61 74 74 61 63 6b 5f 73 79 6e } //1 easy_attack_syn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}