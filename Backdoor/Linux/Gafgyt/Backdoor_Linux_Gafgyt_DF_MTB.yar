
rule Backdoor_Linux_Gafgyt_DF_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.DF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 63 6b 65 74 5f 61 74 74 61 63 6b } //1 socket_attack
		$a_01_1 = {62 6f 74 2e 63 } //1 bot.c
		$a_01_2 = {75 64 70 5f 61 74 74 61 63 6b } //1 udp_attack
		$a_01_3 = {76 73 65 5f 61 74 74 61 63 6b } //1 vse_attack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}