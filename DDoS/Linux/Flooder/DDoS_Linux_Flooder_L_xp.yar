
rule DDoS_Linux_Flooder_L_xp{
	meta:
		description = "DDoS:Linux/Flooder.L!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 64 70 46 6c 6f 6f 64 } //02 00  udpFlood
		$a_01_1 = {61 64 64 55 44 50 } //01 00  addUDP
		$a_01_2 = {49 6e 66 65 63 74 65 75 72 2e 63 } //01 00  Infecteur.c
		$a_01_3 = {73 79 6e 41 74 74 61 63 6b } //01 00  synAttack
		$a_01_4 = {49 6e 66 65 63 74 65 75 72 20 75 64 70 5f 66 6c 6f 6f 64 } //01 00  Infecteur udp_flood
		$a_03_5 = {75 73 61 67 65 3a 20 2e 2f 75 64 70 90 02 20 3c 44 65 73 74 49 70 3e 90 00 } //01 00 
		$a_01_6 = {55 44 50 46 4c 4f 4f 44 20 46 6c 6f 6f 64 20 53 74 61 72 74 20 4f 6e 20 73 74 61 72 74 65 64 } //00 00  UDPFLOOD Flood Start On started
		$a_00_7 = {5d 04 00 00 d9 } //08 05 
	condition:
		any of ($a_*)
 
}