
rule DDoS_Linux_Trigemini_A_xp{
	meta:
		description = "DDoS:Linux/Trigemini.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6e 6a 65 63 74 5f 69 70 68 64 72 } //1 inject_iphdr
		$a_01_1 = {54 3a 55 49 4e 73 3a 68 3a 64 3a 70 3a 71 3a 6c 3a 74 3a } //1 T:UINs:h:d:p:q:l:t:
		$a_01_2 = {74 72 69 67 65 6d 69 6e 69 2e 63 } //1 trigemini.c
		$a_01_3 = {54 43 50 20 41 74 74 61 63 6b } //1 TCP Attack
		$a_01_4 = {54 72 69 47 65 6d 69 6e 69 2e 20 5b 54 43 50 2f 55 44 50 2f 49 43 4d 50 20 50 61 63 6b 65 74 20 66 6c 6f 6f 64 65 72 5d } //1 TriGemini. [TCP/UDP/ICMP Packet flooder]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}