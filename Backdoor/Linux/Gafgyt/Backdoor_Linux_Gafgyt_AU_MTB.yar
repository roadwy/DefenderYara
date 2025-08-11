
rule Backdoor_Linux_Gafgyt_AU_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 72 65 5f 61 74 74 61 63 6b 2e 63 } //1 gre_attack.c
		$a_01_1 = {75 64 70 70 6c 61 69 6e 5f 61 74 74 61 63 6b } //1 udpplain_attack
		$a_01_2 = {2f 74 6d 70 2f 2e 62 6f 74 5f 6c 6f 63 6b } //1 /tmp/.bot_lock
		$a_01_3 = {69 63 6d 70 5f 61 74 74 61 63 6b 2e 63 } //1 icmp_attack.c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}