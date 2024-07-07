
rule Backdoor_Linux_Mirai_AI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 5f 61 6c 6c 5f 72 75 6e 6e 69 6e 67 5f 61 74 74 61 63 6b 73 } //1 kill_all_running_attacks
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_2 = {42 6f 74 20 73 74 61 72 74 65 64 } //1 Bot started
		$a_00_3 = {61 74 74 61 63 6b 5f 75 64 70 } //1 attack_udp
		$a_00_4 = {61 74 74 61 63 6b 5f 73 74 6f 6d 70 } //1 attack_stomp
		$a_00_5 = {73 74 61 72 74 5f 61 74 74 61 63 6b } //1 start_attack
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}