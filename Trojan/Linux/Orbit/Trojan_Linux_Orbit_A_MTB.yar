
rule Trojan_Linux_Orbit_A_MTB{
	meta:
		description = "Trojan:Linux/Orbit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {2f 6c 69 62 2f 90 02 15 2f 73 73 68 70 61 73 73 2e 74 78 74 90 00 } //05 00 
		$a_03_1 = {6d 76 20 2f 6c 69 62 2f 90 02 15 2f 2e 62 61 63 6b 75 70 5f 6c 64 2e 73 6f 90 00 } //05 00 
		$a_01_2 = {2f 74 6d 70 2f 2e 6f 72 62 69 74 } //05 00  /tmp/.orbit
		$a_01_3 = {2f 64 65 76 2f 73 68 6d 2f 2e 6c 63 6b } //01 00  /dev/shm/.lck
		$a_01_4 = {73 6e 69 66 66 5f 73 73 68 5f 73 65 73 73 69 6f 6e } //00 00  sniff_ssh_session
	condition:
		any of ($a_*)
 
}