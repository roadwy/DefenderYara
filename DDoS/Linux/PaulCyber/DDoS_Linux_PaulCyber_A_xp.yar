
rule DDoS_Linux_PaulCyber_A_xp{
	meta:
		description = "DDoS:Linux/PaulCyber.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 79 62 65 72 57 61 72 72 69 6f 72 } //1 CyberWarrior
		$a_01_1 = {49 49 53 44 44 6f 53 20 76 31 2e 30 } //1 IISDDoS v1.0
		$a_01_2 = {64 64 6f 73 2e 69 6e 69 } //1 ddos.ini
		$a_01_3 = {55 73 61 67 65 3a 20 2e 2f 64 64 6f 73 20 3c 69 70 3e 20 5b 3c 6e 75 6d 62 65 72 20 6f 66 20 73 65 72 76 65 72 73 3e 20 5b 3c 73 74 61 72 74 6c 69 6e 65 20 66 72 6f 6d 20 73 65 72 76 65 72 6c 69 73 74 3e 5d 5d } //1 Usage: ./ddos <ip> [<number of servers> [<startline from serverlist>]]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}