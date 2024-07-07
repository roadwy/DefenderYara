
rule HackTool_Linux_Midav_A_xp{
	meta:
		description = "HackTool:Linux/Midav.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 61 64 69 6d 20 6f 6e 20 70 6f 72 74 20 25 64 20 73 70 6f 6f 66 65 64 20 61 73 20 25 73 } //1 Vadim on port %d spoofed as %s
		$a_01_1 = {53 79 6e 74 61 78 3a 20 25 73 20 3c 68 6f 73 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 69 7a 65 3e 20 3c 70 61 63 6b 65 74 73 3e } //1 Syntax: %s <host> <port> <size> <packets>
		$a_01_2 = {53 79 6e 74 61 78 3a 20 25 73 20 3c 68 6f 73 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 70 6f 6f 66 3e } //1 Syntax: %s <host> <port> <spoof>
		$a_01_3 = {46 6c 6f 6f 64 69 6e 67 } //1 Flooding
		$a_01_4 = {56 61 64 69 6d 20 76 } //2 Vadim v
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}