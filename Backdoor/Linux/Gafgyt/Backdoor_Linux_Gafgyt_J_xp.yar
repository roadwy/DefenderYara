
rule Backdoor_Linux_Gafgyt_J_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.J!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 6d 20 2d 72 66 20 2a 3b 20 63 64 20 2f 74 6d 70 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 30 2f 90 02 08 2e 73 68 3b 20 73 68 20 90 02 08 2e 73 68 3b 20 72 6d 20 2d 72 66 20 90 02 08 2e 73 68 3b 90 00 } //01 00 
		$a_00_1 = {73 65 72 76 69 63 65 20 69 70 74 61 62 6c 65 73 20 73 74 6f 70 } //01 00  service iptables stop
		$a_00_2 = {4b 49 4c 4c 41 54 54 4b } //01 00  KILLATTK
		$a_00_3 = {73 65 72 76 69 63 65 20 66 69 72 65 77 61 6c 6c 64 20 73 74 6f 70 } //00 00  service firewalld stop
		$a_00_4 = {5d 04 00 } //00 23 
	condition:
		any of ($a_*)
 
}