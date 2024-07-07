
rule Backdoor_Linux_Dakkatoni_B_xp{
	meta:
		description = "Backdoor:Linux/Dakkatoni.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 74 63 70 } //1 attack_tcp
		$a_00_1 = {61 74 74 61 63 6b 5f 75 64 70 } //1 attack_udp
		$a_00_2 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //1 /usr/sbin/dropbear
		$a_00_3 = {33 31 2e 32 30 32 2e 31 32 38 2e 38 30 } //1 31.202.128.80
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}