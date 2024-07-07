
rule Backdoor_Linux_Gafgyt_R_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.R!xp,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 0c 00 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 54 43 50 } //1 echoTCP
		$a_00_1 = {61 63 6b 66 6c 6f 6f 64 } //1 ackflood
		$a_00_2 = {76 73 65 66 6c 6f 6f 64 } //1 vseflood
		$a_00_3 = {6d 61 6b 65 76 73 65 70 61 63 6b 65 74 } //1 makevsepacket
		$a_00_4 = {73 6f 63 6b 65 74 5f 63 6f 6e 6e 65 63 74 } //1 socket_connect
		$a_00_5 = {65 63 68 6f 78 6d 61 73 } //1 echoxmas
		$a_00_6 = {65 63 68 6f 73 74 64 } //1 echostd
		$a_00_7 = {6f 76 68 66 6c 6f 6f 64 } //1 ovhflood
		$a_00_8 = {65 63 68 6f 63 6f 6d 6d 61 6e 64 } //1 echocommand
		$a_00_9 = {65 63 68 6f 63 6f 6e 6e 65 63 74 69 6f 6e } //1 echoconnection
		$a_00_10 = {5b 54 43 50 40 44 44 6f 53 5d 20 46 6c 6f 6f 64 69 6e 67 20 25 73 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 } //5 [TCP@DDoS] Flooding %s for %d seconds
		$a_00_11 = {5b 55 44 50 40 44 44 6f 53 5d 20 46 6c 6f 6f 64 69 6e 67 20 25 73 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 } //5 [UDP@DDoS] Flooding %s for %d seconds
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*5+(#a_00_11  & 1)*5) >=7
 
}