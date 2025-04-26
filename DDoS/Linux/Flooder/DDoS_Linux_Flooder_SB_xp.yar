
rule DDoS_Linux_Flooder_SB_xp{
	meta:
		description = "DDoS:Linux/Flooder.SB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 0e 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 69 6e 67 20 46 6c 6f 6f 64 2e 2e 2e } //2 Starting Flood...
		$a_01_1 = {4f 70 65 6e 69 6e 67 20 73 6f 63 6b 65 74 73 2e 2e 2e } //2 Opening sockets...
		$a_01_2 = {53 65 6e 64 69 6e 67 20 61 74 74 61 63 6b 2e 2e 2e } //2 Sending attack...
		$a_01_3 = {53 65 74 74 69 6e 67 20 75 70 20 53 6f 63 6b 65 74 73 2e 2e 2e } //2 Setting up Sockets...
		$a_01_4 = {55 73 61 67 65 3a 20 25 73 20 3c 74 61 72 67 65 74 } //2 Usage: %s <target
		$a_01_5 = {55 73 61 67 65 3a 20 25 73 20 3c 49 50 3e 20 3c 74 68 72 65 61 64 73 3e } //2 Usage: %s <IP> <threads>
		$a_01_6 = {3a 3a 20 73 65 6e 64 69 6e 67 20 61 6c 6c 20 74 68 65 20 70 61 63 6b 65 74 73 2e 2e } //2 :: sending all the packets..
		$a_01_7 = {3a 3a 20 63 61 6e 74 20 6f 70 65 6e 20 72 61 77 20 73 6f 63 6b 65 74 2e 20 67 6f 74 20 72 6f 6f 74 } //2 :: cant open raw socket. got root
		$a_01_8 = {3a 3a 20 6d 6f 74 68 65 72 66 75 63 6b 69 6e 67 20 65 72 72 6f 72 2e } //2 :: motherfucking error.
		$a_01_9 = {46 6c 6f 6f 64 69 6e 67 20 25 73 } //2 Flooding %s
		$a_01_10 = {55 44 50 20 46 6c 6f 6f 64 65 72 20 76 31 2e 32 2e 38 20 46 49 4e 41 4c 20 62 79 20 6f 68 6e 6f 65 73 31 34 37 39 } //2 UDP Flooder v1.2.8 FINAL by ohnoes1479
		$a_01_11 = {53 65 6e 64 69 6e 67 20 70 61 63 6b 65 74 73 2e 2e } //2 Sending packets..
		$a_01_12 = {4f 70 65 6e 69 6e 67 20 74 68 72 65 61 64 73 2e 2e 2e } //2 Opening threads...
		$a_01_13 = {55 73 61 67 65 3a 20 25 73 20 5b 49 50 5d } //2 Usage: %s [IP]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2) >=4
 
}