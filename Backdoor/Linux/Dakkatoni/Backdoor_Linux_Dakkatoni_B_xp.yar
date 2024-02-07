
rule Backdoor_Linux_Dakkatoni_B_xp{
	meta:
		description = "Backdoor:Linux/Dakkatoni.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 74 63 70 } //01 00  attack_tcp
		$a_00_1 = {61 74 74 61 63 6b 5f 75 64 70 } //01 00  attack_udp
		$a_00_2 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //01 00  /usr/sbin/dropbear
		$a_00_3 = {33 31 2e 32 30 32 2e 31 32 38 2e 38 30 } //00 00  31.202.128.80
		$a_00_4 = {5d 04 00 } //00 dd 
	condition:
		any of ($a_*)
 
}