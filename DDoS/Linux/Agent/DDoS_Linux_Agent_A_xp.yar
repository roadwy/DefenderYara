
rule DDoS_Linux_Agent_A_xp{
	meta:
		description = "DDoS:Linux/Agent.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //01 00  gethostbyname
		$a_00_1 = {46 41 53 54 5f 46 6c 6f 6f 64 } //01 00  FAST_Flood
		$a_00_2 = {43 6d 64 53 68 65 6c 6c } //01 00  CmdShell
		$a_00_3 = {41 64 6d 69 6e 5f 53 65 72 76 65 72 43 6f 6e 6e 65 63 74 43 6c 69 76 } //01 00  Admin_ServerConnectCliv
		$a_00_4 = {49 43 4d 50 5f 46 6c 6f 6f 64 } //01 00  ICMP_Flood
		$a_00_5 = {53 65 74 44 4e 53 48 65 61 64 50 63 53 5f 69 } //01 00  SetDNSHeadPcS_i
		$a_00_6 = {53 59 4e 5f 46 6c 6f 6f 64 } //01 00  SYN_Flood
		$a_00_7 = {55 44 50 5f 46 6c 6f 6f 64 } //01 00  UDP_Flood
		$a_00_8 = {54 43 50 5f 46 6c 6f 6f 64 } //00 00  TCP_Flood
	condition:
		any of ($a_*)
 
}