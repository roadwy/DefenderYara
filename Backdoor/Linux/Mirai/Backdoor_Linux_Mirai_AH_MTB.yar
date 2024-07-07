
rule Backdoor_Linux_Mirai_AH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 73 74 6f 6d 70 74 63 70 } //1 attack_stomptcp
		$a_00_1 = {73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //1 scanner_kill
		$a_00_2 = {61 74 74 61 63 6b 5f 68 74 68 72 61 78 } //1 attack_hthrax
		$a_00_3 = {61 74 74 61 63 6b 5f 70 6c 61 69 6e 74 63 70 } //1 attack_plaintcp
		$a_00_4 = {63 68 6d 6f 64 20 2b 78 20 25 73 3b 20 2e 2f 25 73 20 25 73 2e 75 70 64 61 74 65 } //1 chmod +x %s; ./%s %s.update
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}