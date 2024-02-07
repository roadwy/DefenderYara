
rule DDoS_Linux_Flooder_F_xp{
	meta:
		description = "DDoS:Linux/Flooder.F!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 6c 6f 6f 64 } //01 00  flood
		$a_00_1 = {6c 64 61 70 2e 63 } //01 00  ldap.c
		$a_00_2 = {53 74 61 72 74 69 6e 67 20 66 6c 6f 6f 64 2e 2e 2e } //01 00  Starting flood...
		$a_00_3 = {25 73 20 49 50 20 50 4f 52 54 20 6c 64 61 70 2e 74 78 74 20 32 20 2d 31 20 54 49 4d 45 } //01 00  %s IP PORT ldap.txt 2 -1 TIME
		$a_00_4 = {55 73 61 67 65 3a 20 25 73 20 3c 74 61 72 67 65 74 20 49 50 3e 20 3c 72 65 66 6c 65 63 74 69 6f 6e 20 66 69 6c 65 3e } //01 00  Usage: %s <target IP> <reflection file>
		$a_00_5 = {55 73 61 67 65 3a 20 25 73 20 3c 74 61 72 67 65 74 20 49 50 3e 20 3c 70 6f 72 74 3e 20 3c 72 65 66 6c 65 63 74 69 6f 6e 20 66 69 6c 65 3e 20 } //01 00  Usage: %s <target IP> <port> <reflection file> 
		$a_00_6 = {46 6c 6f 6f 64 65 64 20 62 79 20 4b 65 69 6a 79 79 21 2e 2e 2e } //01 00  Flooded by Keijyy!...
		$a_00_7 = {55 7a 79 63 69 65 3a 20 25 73 20 3c 69 70 20 67 72 79 3e 20 3c 70 6f 72 74 20 67 72 79 3e 20 } //01 00  Uzycie: %s <ip gry> <port gry> 
		$a_00_8 = {53 74 61 72 74 20 55 70 20 44 44 4f 53 2e 2e 2e } //00 00  Start Up DDOS...
		$a_00_9 = {5d 04 00 } //00 d3 
	condition:
		any of ($a_*)
 
}