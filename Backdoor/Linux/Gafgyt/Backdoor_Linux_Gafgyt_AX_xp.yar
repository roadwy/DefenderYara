
rule Backdoor_Linux_Gafgyt_AX_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AX!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 63 70 63 73 75 6d } //02 00  tcpcsum
		$a_01_1 = {72 61 6e 64 5f 63 6d 77 63 } //02 00  rand_cmwc
		$a_01_2 = {63 68 65 63 6b 73 75 6d 5f 74 63 70 5f 75 64 70 } //02 00  checksum_tcp_udp
		$a_01_3 = {62 75 73 79 62 6f 78 74 65 72 72 6f 72 69 73 74 } //02 00  busyboxterrorist
		$a_01_4 = {42 6f 74 6b 69 6c 6c } //02 00  Botkill
		$a_01_5 = {53 45 4e 44 42 4f 54 53 54 4f } //01 00  SENDBOTSTO
		$a_01_6 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //01 00  /usr/sbin/dropbear
		$a_01_7 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_01_8 = {68 6c 4c 6a 7a 74 71 5a } //00 00  hlLjztqZ
		$a_00_9 = {5d 04 00 00 } //d2 16 
	condition:
		any of ($a_*)
 
}