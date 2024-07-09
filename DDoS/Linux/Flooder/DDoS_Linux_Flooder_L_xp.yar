
rule DDoS_Linux_Flooder_L_xp{
	meta:
		description = "DDoS:Linux/Flooder.L!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 64 70 46 6c 6f 6f 64 } //2 udpFlood
		$a_01_1 = {61 64 64 55 44 50 } //2 addUDP
		$a_01_2 = {49 6e 66 65 63 74 65 75 72 2e 63 } //1 Infecteur.c
		$a_01_3 = {73 79 6e 41 74 74 61 63 6b } //1 synAttack
		$a_01_4 = {49 6e 66 65 63 74 65 75 72 20 75 64 70 5f 66 6c 6f 6f 64 } //1 Infecteur udp_flood
		$a_03_5 = {75 73 61 67 65 3a 20 2e 2f 75 64 70 [0-20] 3c 44 65 73 74 49 70 3e } //1
		$a_01_6 = {55 44 50 46 4c 4f 4f 44 20 46 6c 6f 6f 64 20 53 74 61 72 74 20 4f 6e 20 73 74 61 72 74 65 64 } //1 UDPFLOOD Flood Start On started
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}