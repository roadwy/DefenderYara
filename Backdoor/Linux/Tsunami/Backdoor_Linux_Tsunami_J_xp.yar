
rule Backdoor_Linux_Tsunami_J_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.J!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 46 4c 4f 4f 44 } //1 HTTPFLOOD
		$a_01_1 = {54 43 50 46 4c 4f 4f 44 } //1 TCPFLOOD
		$a_01_2 = {55 44 50 46 4c 4f 4f 44 } //1 UDPFLOOD
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 5b 25 73 5d 20 7b 54 43 50 46 4c 4f 4f 44 7d 20 53 74 61 72 74 65 64 20 73 65 6e 64 69 6e 67 20 74 63 70 20 64 61 74 61 20 74 6f 20 68 6f 73 74 20 25 73 20 6f 6e 20 70 6f 72 74 20 25 64 20 28 25 73 29 } //1 PRIVMSG %s :[%s] {TCPFLOOD} Started sending tcp data to host %s on port %d (%s)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}