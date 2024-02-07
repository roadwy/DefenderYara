
rule Backdoor_Linux_XorDDoSRootkit_A{
	meta:
		description = "Backdoor:Linux/XorDDoSRootkit.A,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 69 72 65 77 61 6c 6c 5f 61 63 63 65 70 74 69 70 } //01 00  firewall_acceptip
		$a_00_1 = {66 69 72 65 77 61 6c 6c 5f 64 72 6f 70 69 70 } //01 00  firewall_dropip
		$a_00_2 = {75 6e 66 69 72 65 77 61 6c 6c 5f 64 72 6f 70 69 70 } //01 00  unfirewall_dropip
		$a_00_3 = {75 6e 66 69 72 65 77 61 6c 6c 5f 61 63 63 65 70 74 69 70 } //01 00  unfirewall_acceptip
		$a_00_4 = {75 6e 68 69 64 65 5f 75 64 70 36 5f 70 6f 72 74 } //01 00  unhide_udp6_port
		$a_00_5 = {68 69 64 65 5f 75 64 70 34 5f 70 6f 72 74 } //01 00  hide_udp4_port
		$a_00_6 = {68 69 64 65 5f 75 64 70 36 5f 70 6f 72 74 } //01 00  hide_udp6_port
		$a_00_7 = {68 69 64 65 5f 74 63 70 34 5f 70 6f 72 74 } //01 00  hide_tcp4_port
		$a_00_8 = {68 69 64 65 5f 74 63 70 36 5f 70 6f 72 74 } //01 00  hide_tcp6_port
		$a_00_9 = {68 69 64 64 65 6e 5f 74 63 70 36 5f 70 6f 72 74 73 } //01 00  hidden_tcp6_ports
		$a_00_10 = {68 69 64 65 5f 66 69 6c 65 } //02 00  hide_file
		$a_00_11 = {6b 4f 5f 63 6f 70 79 5f 66 72 6f 6d 5f 75 73 65 72 } //00 00  kO_copy_from_user
	condition:
		any of ($a_*)
 
}