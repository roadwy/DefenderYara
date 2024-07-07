
rule Backdoor_Linux_Blakken_A_xp{
	meta:
		description = "Backdoor:Linux/Blakken.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 6c 4c 6a 7a 74 71 } //1 hlLjztq
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 6e 63 73 } //1 npxXoudifFeEgGaACSncs
		$a_00_2 = {75 64 70 66 6c 6f 6f 64 } //1 udpflood
		$a_00_3 = {74 63 70 63 6f 6e 6e 65 63 74 } //1 tcpconnect
		$a_00_4 = {68 74 74 70 66 6c 6f 6f 64 } //1 httpflood
		$a_00_5 = {64 6e 73 66 6c 6f 6f 64 } //1 dnsflood
		$a_00_6 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //1 Multihop attempted
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}