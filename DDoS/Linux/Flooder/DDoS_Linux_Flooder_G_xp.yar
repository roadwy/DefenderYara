
rule DDoS_Linux_Flooder_G_xp{
	meta:
		description = "DDoS:Linux/Flooder.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 0e 00 00 "
		
	strings :
		$a_01_0 = {66 6c 6f 6f 64 70 6f 72 74 } //1 floodport
		$a_01_1 = {42 72 6f 77 6e 53 74 61 72 54 65 61 6d } //1 BrownStarTeam
		$a_01_2 = {42 30 53 54 41 4e 4c 49 } //1 B0STANLI
		$a_01_3 = {74 63 70 63 73 75 6d } //1 tcpcsum
		$a_01_4 = {53 70 6f 6f 66 65 64 20 55 44 50 20 46 6c 6f 6f 64 65 72 } //1 Spoofed UDP Flooder
		$a_01_5 = {53 53 59 4e 20 46 6c 6f 6f 64 65 72 20 62 79 20 4c 53 44 45 56 } //1 SSYN Flooder by LSDEV
		$a_01_6 = {7a 65 6c 20 44 44 6f 53 20 53 63 72 69 70 74 2e } //1 zel DDoS Script.
		$a_01_7 = {25 73 20 3c 49 50 3e 20 3c 50 6f 72 74 3e } //1 %s <IP> <Port>
		$a_01_8 = {25 73 20 3c 74 61 72 67 65 74 20 49 50 3e 20 3c 70 6f 72 74 20 74 6f 20 62 65 20 66 6c 6f 6f 64 65 64 3e } //1 %s <target IP> <port to be flooded>
		$a_01_9 = {6d 3a 20 25 73 20 3c 68 65 64 65 66 20 49 50 3e 20 3c 74 61 72 67 65 74 20 50 6f 72 74 3e } //1 m: %s <hedef IP> <target Port>
		$a_01_10 = {44 44 4f 53 54 48 41 49 4c 41 4e 44 2e 58 59 5a } //1 DDOSTHAILAND.XYZ
		$a_01_11 = {42 41 4e 4b 54 59 20 44 44 4f 53 20 46 4f 52 20 46 41 52 4b 48 4f 53 54 20 52 41 4e 44 4f 4d 2e 2e } //1 BANKTY DDOS FOR FARKHOST RANDOM..
		$a_01_12 = {53 74 61 72 74 69 6e 67 20 46 6c 6f 6f 64 20 4f 6e 20 58 62 6f 78 20 4c 69 76 65 2e 2e 2e } //1 Starting Flood On Xbox Live...
		$a_01_13 = {41 74 74 61 63 6b 69 6e 67 20 53 74 61 72 74 65 64 2e 2e } //1 Attacking Started..
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=2
 
}